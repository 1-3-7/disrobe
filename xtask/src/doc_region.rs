use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;
const OPEN_SUFFIX: &str = " -->";

#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    Write,
    Check,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegionSyntax {
    pub(crate) open_prefix: &'static str,
    pub(crate) close: &'static str,
}

#[derive(Debug)]
pub(crate) struct Region {
    pub(crate) slug: String,
    pub(crate) line: usize,
    pub(crate) content: String,
    content_start: usize,
    content_end: usize,
}

pub(crate) fn parse(syntax: RegionSyntax, text: &str) -> Result<Vec<Region>> {
    let RegionSyntax { open_prefix, close }: RegionSyntax = syntax;
    let mut out: Vec<Region> = Vec::new();
    let mut offset: usize = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = index + 1;
        let mut search_from: usize = 0;
        while let Some(rel) = line
            .get(search_from..)
            .and_then(|rest: &str| rest.find(open_prefix))
        {
            let open_at: usize = search_from + rel;
            let after_prefix: usize = open_at + open_prefix.len();
            let Some(suffix_rel) = line
                .get(after_prefix..)
                .and_then(|rest: &str| rest.find(OPEN_SUFFIX))
            else {
                bail!(
                    "line {line_no}: a `{open_prefix}` opening has no `{OPEN_SUFFIX}` on the same \
                     line"
                );
            };
            let slug: &str = line
                .get(after_prefix..after_prefix + suffix_rel)
                .unwrap_or_default();
            let content_from: usize = after_prefix + suffix_rel + OPEN_SUFFIX.len();
            let Some(close_rel) = line
                .get(content_from..)
                .and_then(|rest: &str| rest.find(close))
            else {
                bail!("line {line_no}: the region `{slug}` has no `{close}` on the same line");
            };
            let content_end: usize = content_from + close_rel;
            out.push(Region {
                slug: slug.to_owned(),
                line: line_no,
                content: line
                    .get(content_from..content_end)
                    .unwrap_or_default()
                    .to_owned(),
                content_start: offset + content_from,
                content_end: offset + content_end,
            });
            search_from = content_end + close.len();
        }
        offset += line.len();
    }
    Ok(out)
}

pub(crate) fn rewrite(
    syntax: RegionSyntax,
    text: &str,
    render: &dyn Fn(&str) -> Result<String>,
) -> Result<String> {
    let regions: Vec<Region> = parse(syntax, text)?;
    if regions.is_empty() {
        return Ok(text.to_owned());
    }
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for region in &regions {
        let rendered: String = render(&region.slug)
            .wrap_err_with(|| format!("line {}: rendering `{}`", region.line, region.slug))?;
        out.push_str(text.get(cursor..region.content_start).unwrap_or_default());
        out.push_str(&rendered);
        cursor = region.content_end;
    }
    out.push_str(text.get(cursor..).unwrap_or_default());
    Ok(out)
}

pub(crate) fn manifest(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![root.join("README.md")];
    let docs_src: PathBuf = root.join("docs").join("src");
    if docs_src.is_dir() {
        for entry in walkdir::WalkDir::new(&docs_src) {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", docs_src.display()))?;
            let path: &Path = dirent.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md") {
                files.push(path.to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(crate) fn read_doc(path: &Path) -> Result<String> {
    read_text_bounded(path, MAX_DOC_BYTES).wrap_err_with(|| format!("reading {}", path.display()))
}

pub(crate) fn label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTAX: RegionSyntax = RegionSyntax {
        open_prefix: "<!-- t:",
        close: "<!-- /t -->",
    };

    #[test]
    fn a_region_is_located_with_its_slug_and_content() -> Result<()> {
        let text: &str = "a <!-- t:one -->x<!-- /t --> b <!-- t:two -->y<!-- /t -->\n";
        let regions: Vec<Region> = parse(SYNTAX, text)?;
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].slug, "one");
        assert_eq!(regions[0].content, "x");
        assert_eq!(regions[1].slug, "two");
        assert_eq!(regions[1].content, "y");
        Ok(())
    }

    #[test]
    fn a_rewrite_is_a_fixpoint() -> Result<()> {
        let text: &str = "a <!-- t:one -->stale<!-- /t -->\n";
        let render = |slug: &str| -> Result<String> { Ok(format!("[{slug}]")) };
        let once: String = rewrite(SYNTAX, text, &render)?;
        let twice: String = rewrite(SYNTAX, &once, &render)?;
        assert_eq!(once, "a <!-- t:one -->[one]<!-- /t -->\n");
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn an_unclosed_region_is_refused() {
        assert!(parse(SYNTAX, "a <!-- t:one -->x\n").is_err());
    }
}
