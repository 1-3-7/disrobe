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

const MAX_SIBLING_MAP_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SiblingMapRefusal {
    #[error("the source map reference is empty")]
    Empty,
    #[error(
        "`{0}` names a URL scheme, drive or device; only a path inside the input's directory is followed"
    )]
    SchemeOrDrive(String),
    #[error(
        "`{0}` is an absolute or UNC path; only a path inside the input's directory is followed"
    )]
    Absolute(String),
    #[error("`{0}` climbs out of the input's directory with `..`")]
    ParentTraversal(String),
    #[error("`{0}` resolves outside the input's directory")]
    OutsideInputDirectory(String),
    #[error("`{url}` is {size} bytes, above the {MAX_SIBLING_MAP_BYTES}-byte cap")]
    TooLarge { url: String, size: u64 },
}

pub fn sibling_map_path(
    input_dir: &std::path::Path,
    url: &str,
) -> Result<std::path::PathBuf, SiblingMapRefusal> {
    let trimmed: &str = url.trim();
    if trimmed.is_empty() {
        return Err(SiblingMapRefusal::Empty);
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(SiblingMapRefusal::Absolute(trimmed.to_owned()));
    }
    if trimmed.contains(':') || trimmed.contains('\0') {
        return Err(SiblingMapRefusal::SchemeOrDrive(trimmed.to_owned()));
    }
    if trimmed
        .split(['/', '\\'])
        .any(|component: &str| component == "..")
    {
        return Err(SiblingMapRefusal::ParentTraversal(trimmed.to_owned()));
    }
    Ok(input_dir.join(trimmed))
}

pub fn contained_sibling_map(
    input_dir: &std::path::Path,
    resolved: &std::path::Path,
    url: &str,
) -> Result<(), SiblingMapRefusal> {
    let outside = || SiblingMapRefusal::OutsideInputDirectory(url.to_owned());
    let dir: std::path::PathBuf = input_dir.canonicalize().map_err(|_| outside())?;
    let file: std::path::PathBuf = resolved.canonicalize().map_err(|_| outside())?;
    if !file.starts_with(&dir) {
        return Err(outside());
    }
    let size: u64 = std::fs::metadata(&file).map_err(|_| outside())?.len();
    if size > MAX_SIBLING_MAP_BYTES {
        return Err(SiblingMapRefusal::TooLarge {
            url: url.to_owned(),
            size,
        });
    }
    Ok(())
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
    fn sibling_map_paths_outside_the_input_directory_are_refused_by_kind() {
        let dir: &std::path::Path = std::path::Path::new("in");
        let cases: [(&str, SiblingMapRefusal); 9] = [
            ("", SiblingMapRefusal::Empty),
            (
                "../x.map",
                SiblingMapRefusal::ParentTraversal("../x.map".to_owned()),
            ),
            (
                "a/../../x.map",
                SiblingMapRefusal::ParentTraversal("a/../../x.map".to_owned()),
            ),
            (
                r"..\x.map",
                SiblingMapRefusal::ParentTraversal(r"..\x.map".to_owned()),
            ),
            (
                "/etc/x.map",
                SiblingMapRefusal::Absolute("/etc/x.map".to_owned()),
            ),
            (
                r"\\host\share\x.map",
                SiblingMapRefusal::Absolute(r"\\host\share\x.map".to_owned()),
            ),
            (
                "//host/share/x.map",
                SiblingMapRefusal::Absolute("//host/share/x.map".to_owned()),
            ),
            (
                r"C:\x.map",
                SiblingMapRefusal::SchemeOrDrive(r"C:\x.map".to_owned()),
            ),
            (
                "https://example.com/x.map",
                SiblingMapRefusal::SchemeOrDrive("https://example.com/x.map".to_owned()),
            ),
        ];
        for (url, refusal) in cases {
            assert_eq!(sibling_map_path(dir, url), Err(refusal), "{url}");
        }
        assert_eq!(
            sibling_map_path(dir, "maps/app.js.map"),
            Ok(dir.join("maps/app.js.map"))
        );
    }

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
