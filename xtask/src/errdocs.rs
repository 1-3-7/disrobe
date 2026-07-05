use std::fmt::Arguments;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_REGISTRY_SOURCE_BYTES: u64 = 1024 * 1024;

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ErrorCode {
    pub(crate) code: String,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) common_causes: Vec<String>,
    pub(crate) common_fixes: Vec<String>,
    pub(crate) crate_path: String,
}

#[must_use]
pub(crate) fn registry_dir(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join("crates")
        .join("disrobe-cli")
        .join("src")
        .join("cli")
        .join("explain")
        .join("codes")
}

#[must_use]
pub(crate) fn errors_doc_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join("docs").join("errors")
}

pub(crate) fn parse_registry(registry_dir: &Path) -> Result<Vec<ErrorCode>> {
    let mut sources: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(registry_dir)
        .with_context_str(|| format!("reading registry dir {}", registry_dir.display()))?
    {
        let path: PathBuf = entry?.path();
        let is_code_file: bool = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "rs")
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n != "mod.rs");
        if is_code_file {
            sources.push(path);
        }
    }
    sources.sort();

    let mut codes: Vec<ErrorCode> = Vec::new();
    for source in &sources {
        let text: String = read_text_bounded(source, MAX_REGISTRY_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", source.display()))?;
        parse_source(&text, &mut codes)
            .wrap_err_with(|| format!("parsing {}", source.display()))?;
    }
    if codes.is_empty() {
        bail!(
            "registry parse produced zero codes in {}",
            registry_dir.display()
        );
    }
    codes.sort_by(|a: &ErrorCode, b: &ErrorCode| a.code.cmp(&b.code));
    codes.dedup_by(|a: &mut ErrorCode, b: &mut ErrorCode| a.code == b.code);
    Ok(codes)
}

fn parse_source(text: &str, out: &mut Vec<ErrorCode>) -> Result<()> {
    let chars: Vec<char> = text.chars().collect();
    let mut pos: usize = 0;
    let mut current: Option<ErrorCode> = None;
    while pos < chars.len() {
        let Some((name, after_colon)): Option<(String, usize)> = next_field(&chars, pos) else {
            break;
        };
        match name.as_str() {
            "code" => {
                if let Some(done) = current.take() {
                    out.push(done);
                }
                let (value, next): (String, usize) = read_string(&chars, after_colon)?;
                current = Some(ErrorCode {
                    code: value,
                    title: String::new(),
                    description: String::new(),
                    common_causes: Vec::new(),
                    common_fixes: Vec::new(),
                    crate_path: String::new(),
                });
                pos = next;
            }
            "title" | "description" | "crate_path" => {
                let (value, next): (String, usize) = read_string(&chars, after_colon)?;
                if let Some(entry) = current.as_mut() {
                    match name.as_str() {
                        "title" => entry.title = value,
                        "description" => entry.description = value,
                        _ => entry.crate_path = value,
                    }
                }
                pos = next;
            }
            "common_causes" | "common_fixes" => {
                let (values, next): (Vec<String>, usize) = read_array(&chars, after_colon)?;
                if let Some(entry) = current.as_mut() {
                    if name == "common_causes" {
                        entry.common_causes = values;
                    } else {
                        entry.common_fixes = values;
                    }
                }
                pos = next;
            }
            _ => {
                pos = after_colon;
            }
        }
    }
    if let Some(done) = current.take() {
        out.push(done);
    }
    Ok(())
}

fn next_field(chars: &[char], from: usize) -> Option<(String, usize)> {
    let mut i: usize = from;
    while i < chars.len() {
        let c: char = chars[i];
        if c == '"' {
            i = skip_string(chars, i + 1);
            continue;
        }
        if c == '_' || c.is_ascii_alphabetic() {
            let start: usize = i;
            while i < chars.len() && (chars[i] == '_' || chars[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let mut j: usize = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && chars[j] == ':' {
                let name: String = chars[start..i].iter().collect();
                return Some((name, j + 1));
            }
            continue;
        }
        i += 1;
    }
    None
}

fn skip_string(chars: &[char], from: usize) -> usize {
    let mut i: usize = from;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

fn read_string(chars: &[char], from: usize) -> Result<(String, usize)> {
    let mut i: usize = from;
    while i < chars.len() && chars[i] != '"' {
        i += 1;
    }
    if i >= chars.len() {
        bail!("expected opening quote after field");
    }
    let (value, end): (String, usize) = take_string_body(chars, i + 1)?;
    Ok((value, end))
}

fn take_string_body(chars: &[char], from: usize) -> Result<(String, usize)> {
    let mut raw: String = String::new();
    let mut i: usize = from;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if i + 1 >= chars.len() {
                    bail!("trailing backslash in string literal");
                }
                raw.push('\\');
                raw.push(chars[i + 1]);
                i += 2;
            }
            '"' => return Ok((unescape(&raw), i + 1)),
            other => {
                raw.push(other);
                i += 1;
            }
        }
    }
    bail!("unterminated string literal")
}

fn read_array(chars: &[char], from: usize) -> Result<(Vec<String>, usize)> {
    let mut i: usize = from;
    while i < chars.len() && chars[i] != '[' {
        i += 1;
    }
    if i >= chars.len() {
        bail!("expected `[` for array field");
    }
    i += 1;
    let mut items: Vec<String> = Vec::new();
    while i < chars.len() {
        match chars[i] {
            ']' => return Ok((items, i + 1)),
            '"' => {
                let (value, end): (String, usize) = take_string_body(chars, i + 1)?;
                items.push(value);
                i = end;
            }
            _ => i += 1,
        }
    }
    bail!("unterminated array literal")
}

fn unescape(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    let mut chars: std::str::Chars<'_> = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('0') => out.push('\0'),
                Some('\\') | None => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[must_use]
pub(crate) fn render(code: &ErrorCode) -> String {
    let mut md: String = String::with_capacity(512);
    push_line!(md, "# {}", code.code);
    md.push('\n');
    push_line!(md, "**{}**", code.title);
    md.push('\n');
    push_line!(md, "{}", code.description);
    md.push('\n');
    if !code.common_causes.is_empty() {
        md.push_str("## Common causes\n\n");
        for cause in &code.common_causes {
            push_line!(md, "- {cause}");
        }
        md.push('\n');
    }
    if !code.common_fixes.is_empty() {
        md.push_str("## Common fixes\n\n");
        for fix in &code.common_fixes {
            push_line!(md, "- {fix}");
        }
        md.push('\n');
    }
    md.push_str("## Source\n\n");
    push_line!(md, "Emitted from `{}`.\n", code.crate_path);
    push_line!(
        md,
        "Look this up at runtime with `disrobe explain {}`.",
        code.code
    );
    md
}

#[must_use]
pub(crate) fn render_index(codes: &[ErrorCode]) -> String {
    let mut md: String = String::with_capacity(codes.len() * 64 + 256);
    md.push_str("# Error codes\n\n");
    md.push_str(
        "Every emittable `DR-<DOMAIN>-<NNNN>` diagnostic has a page here, generated from the in-tree registry at `crates/disrobe-cli/src/cli/explain/codes/`. Look any code up at runtime with `disrobe explain <code>`.\n\n",
    );
    md.push_str("| Code | Title |\n");
    md.push_str("|---|---|\n");
    for code in codes {
        push_line!(
            md,
            "| [{}](./{}.md) | {} |",
            code.code,
            code.code,
            code.title
        );
    }
    md
}

pub(crate) fn generate(workspace_root: &Path) -> Result<usize> {
    generate_into(workspace_root, &errors_doc_dir(workspace_root))
}

pub(crate) fn generate_into(workspace_root: &Path, out_dir: &Path) -> Result<usize> {
    let registry: PathBuf = registry_dir(workspace_root);
    let codes: Vec<ErrorCode> = parse_registry(&registry)?;
    fs::create_dir_all(out_dir).with_context_str(|| format!("creating {}", out_dir.display()))?;
    for code in &codes {
        let path: PathBuf = out_dir.join(format!("{}.md", code.code));
        fs::write(&path, render(code))
            .with_context_str(|| format!("writing {}", path.display()))?;
    }
    let index_path: PathBuf = out_dir.join("README.md");
    fs::write(&index_path, render_index(&codes))
        .with_context_str(|| format!("writing {}", index_path.display()))?;
    Ok(codes.len())
}

trait WithContextStr<T> {
    fn with_context_str<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E> WithContextStr<T> for core::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context_str<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.wrap_err_with(f)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_entry() {
        let src: &str = r#"
        CodeEntry {
            code: "DR-CLI-0001",
            title: "cannot read file",
            description: "the path could not be read.",
            common_causes: &["file does not exist", "permission denied"],
            common_fixes: &["verify the path", "check permissions"],
            crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
        },
        "#;
        let mut out: Vec<ErrorCode> = Vec::new();
        parse_source(src, &mut out).expect("parse");
        assert_eq!(out.len(), 1);
        let entry: &ErrorCode = &out[0];
        assert_eq!(entry.code, "DR-CLI-0001");
        assert_eq!(entry.title, "cannot read file");
        assert_eq!(entry.common_causes.len(), 2);
        assert_eq!(entry.common_fixes[0], "verify the path");
        assert_eq!(entry.crate_path, "crates/disrobe-cli/src/cli/pyarmor.rs");
    }

    #[test]
    fn rendered_doc_carries_code_and_title() {
        let code: ErrorCode = ErrorCode {
            code: "DR-CLI-0001".to_owned(),
            title: "cannot read file".to_owned(),
            description: "the path could not be read.".to_owned(),
            common_causes: vec!["file does not exist".to_owned()],
            common_fixes: vec!["verify the path".to_owned()],
            crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs".to_owned(),
        };
        let md: String = render(&code);
        assert!(md.starts_with("# DR-CLI-0001\n"));
        assert!(md.contains("cannot read file"));
        assert!(md.contains("disrobe explain DR-CLI-0001"));
    }
}
