use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use proc_macro2::{Delimiter, LineColumn, Span, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::visit::Visit;

use crate::errdocs;
use crate::fileio::read_text_bounded;

const MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 20_000;
const MAX_EMISSION_SITES: usize = 50_000;
const MAX_TOKEN_DEPTH: usize = 128;
const MAX_MESSAGE_CHARS: usize = 4_096;
const REPORT_PATH: [&str; 3] = ["evidence", "errcodes", "collisions.md"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanLimit {
    SourceFiles {
        limit: usize,
    },
    EmissionSites {
        limit: usize,
    },
    TokenDepth {
        path: String,
        line: usize,
        limit: usize,
    },
    MessageLength {
        path: String,
        line: usize,
        limit: usize,
    },
}

impl fmt::Display for ScanLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceFiles { limit } => {
                write!(
                    formatter,
                    "more than {limit} Rust sources under crates/*/src"
                )
            }
            Self::EmissionSites { limit } => {
                write!(formatter, "more than {limit} error-code emission sites")
            }
            Self::TokenDepth { path, line, limit } => write!(
                formatter,
                "{path}:{line}: macro or attribute tokens nest deeper than {limit} groups"
            ),
            Self::MessageLength { path, line, limit } => write!(
                formatter,
                "{path}:{line}: error-code literal is longer than {limit} characters"
            ),
        }
    }
}

impl std::error::Error for ScanLimit {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Site {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CodeUse {
    pub(crate) messages: BTreeMap<String, Vec<Site>>,
    pub(crate) bare: Vec<Site>,
}

impl CodeUse {
    fn site_count(&self) -> usize {
        self.bare.len() + self.messages.values().map(Vec::len).sum::<usize>()
    }

    fn all_sites(&self) -> Vec<&Site> {
        let mut sites: Vec<&Site> = self.messages.values().flatten().chain(&self.bare).collect();
        sites.sort();
        sites
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Census {
    pub(crate) scanned_files: usize,
    pub(crate) emitted: BTreeMap<String, CodeUse>,
    pub(crate) registered: BTreeSet<String>,
}

impl Census {
    fn site_count(&self) -> usize {
        self.emitted.values().map(CodeUse::site_count).sum()
    }

    fn message_site_count(&self) -> usize {
        self.emitted
            .values()
            .map(|usage: &CodeUse| usage.messages.values().map(Vec::len).sum::<usize>())
            .sum()
    }

    pub(crate) fn collisions(&self) -> Vec<(&str, &CodeUse)> {
        self.emitted
            .iter()
            .filter(|(_, usage): &(&String, &CodeUse)| usage.messages.len() >= 2)
            .map(|(code, usage): (&String, &CodeUse)| (code.as_str(), usage))
            .collect()
    }

    pub(crate) fn unregistered(&self) -> Vec<(&str, &CodeUse)> {
        self.emitted
            .iter()
            .filter(|(code, _): &(&String, &CodeUse)| !self.registered.contains(*code))
            .map(|(code, usage): (&String, &CodeUse)| (code.as_str(), usage))
            .collect()
    }

    pub(crate) fn unemitted(&self) -> Vec<&str> {
        self.registered
            .iter()
            .filter(|code: &&String| !self.emitted.contains_key(*code))
            .map(String::as_str)
            .collect()
    }
}

pub(crate) fn report_path(root: &Path) -> PathBuf {
    REPORT_PATH
        .iter()
        .fold(root.to_path_buf(), |path: PathBuf, part: &&str| {
            path.join(part)
        })
}

pub(crate) fn run(root: &Path, check: bool, strict: bool) -> Result<()> {
    let census: Census = scan(root, &errdocs::registry_dir(root))?;
    let report: String = render(&census);
    let path: PathBuf = report_path(root);
    let shown: String = REPORT_PATH.join("/");
    if check {
        let committed: String = read_text_bounded(&path, MAX_REPORT_BYTES)
            .wrap_err_with(|| format!("reading the committed report {shown}"))?;
        if committed != report {
            bail!("{shown} is stale; run `cargo run -p xtask -- errcodes`");
        }
        println!("xtask errcodes --check: {shown} matches a fresh scan");
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&path, &report).wrap_err_with(|| format!("writing {shown}"))?;
        println!(
            "xtask errcodes: {} site(s), {} code(s), {} with two or more messages, {} unregistered, {} registered but not emitted; wrote {shown}",
            census.site_count(),
            census.emitted.len(),
            census.collisions().len(),
            census.unregistered().len(),
            census.unemitted().len()
        );
    }
    if strict {
        enforce_strict(&census)?;
    }
    Ok(())
}

pub(crate) fn enforce_strict(census: &Census) -> Result<()> {
    let collided: Vec<&str> = census
        .collisions()
        .into_iter()
        .map(|(code, _): (&str, &CodeUse)| code)
        .collect();
    let unregistered: Vec<&str> = census
        .unregistered()
        .into_iter()
        .map(|(code, _): (&str, &CodeUse)| code)
        .collect();
    if collided.is_empty() && unregistered.is_empty() {
        return Ok(());
    }
    bail!(
        "{} code(s) carry two or more messages [{}]; {} emitted code(s) are not registered [{}]",
        collided.len(),
        collided.join(", "),
        unregistered.len(),
        unregistered.join(", ")
    )
}

pub(crate) fn scan(root: &Path, registry_dir: &Path) -> Result<Census> {
    let registered: BTreeSet<String> = errdocs::parse_registry(registry_dir)?
        .into_iter()
        .map(|entry: errdocs::ErrorCode| entry.code)
        .collect();
    let sources: Vec<PathBuf> = source_files(root, registry_dir)?;
    let mut scans: Vec<FileScan> = Vec::with_capacity(sources.len());
    for source in &sources {
        scans.push(scan_file(root, source)?);
    }
    let test_modules: Vec<PathBuf> = scans
        .iter()
        .flat_map(|scan: &FileScan| scan.test_modules.iter().cloned())
        .collect();
    let mut census: Census = Census {
        scanned_files: 0,
        emitted: BTreeMap::new(),
        registered,
    };
    let mut sites: usize = 0;
    for scan in scans {
        if test_modules
            .iter()
            .any(|module: &PathBuf| scan.path.starts_with(module))
        {
            continue;
        }
        census.scanned_files += 1;
        for literal in &scan.literals {
            for (code, message) in codes_in(&literal.text) {
                if message
                    .as_ref()
                    .is_some_and(|text: &String| text.chars().count() > MAX_MESSAGE_CHARS)
                {
                    return Err(ScanLimit::MessageLength {
                        path: scan.relative.clone(),
                        line: literal.line,
                        limit: MAX_MESSAGE_CHARS,
                    }
                    .into());
                }
                sites += 1;
                if sites > MAX_EMISSION_SITES {
                    return Err(ScanLimit::EmissionSites {
                        limit: MAX_EMISSION_SITES,
                    }
                    .into());
                }
                let site: Site = Site {
                    path: scan.relative.clone(),
                    line: literal.line,
                    column: literal.column,
                };
                let usage: &mut CodeUse = census.emitted.entry(code).or_default();
                match message {
                    Some(text) => usage.messages.entry(text).or_default().push(site),
                    None => usage.bare.push(site),
                }
            }
        }
    }
    for usage in census.emitted.values_mut() {
        usage.bare.sort();
        for sites in usage.messages.values_mut() {
            sites.sort();
        }
    }
    Ok(census)
}

fn source_files(root: &Path, registry_dir: &Path) -> Result<Vec<PathBuf>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut crate_dirs: Vec<PathBuf> = Vec::new();
    for entry in
        fs::read_dir(&crates_dir).wrap_err_with(|| format!("reading {}", crates_dir.display()))?
    {
        let path: PathBuf = entry
            .wrap_err_with(|| format!("reading an entry of {}", crates_dir.display()))?
            .path();
        if path.join("src").is_dir() {
            crate_dirs.push(path.join("src"));
        }
    }
    crate_dirs.sort();
    let mut sources: Vec<PathBuf> = Vec::new();
    for src in crate_dirs {
        for entry in walkdir::WalkDir::new(&src).sort_by_file_name() {
            let entry: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", src.display()))?;
            let path: &Path = entry.path();
            let is_rust: bool = entry.file_type().is_file()
                && path.extension().is_some_and(|extension| extension == "rs");
            if !is_rust || path.starts_with(registry_dir) {
                continue;
            }
            if sources.len() >= MAX_SOURCE_FILES {
                return Err(ScanLimit::SourceFiles {
                    limit: MAX_SOURCE_FILES,
                }
                .into());
            }
            sources.push(path.to_path_buf());
        }
    }
    Ok(sources)
}

#[derive(Debug)]
struct Literal {
    text: String,
    line: usize,
    column: usize,
}

#[derive(Debug)]
struct FileScan {
    path: PathBuf,
    relative: String,
    literals: Vec<Literal>,
    test_modules: Vec<PathBuf>,
}

fn scan_file(root: &Path, path: &Path) -> Result<FileScan> {
    let relative: String = relative_path(root, path);
    let text: String = read_text_bounded(path, MAX_SOURCE_FILE_BYTES)?;
    let file: syn::File =
        syn::parse_file(&text).wrap_err_with(|| format!("parsing {relative} as Rust"))?;
    let file_dir: PathBuf = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let module_dir: PathBuf = if owns_directory(path) {
        file_dir.clone()
    } else {
        path.with_extension("")
    };
    let mut collector: LiteralCollector<'_> = LiteralCollector {
        relative: &relative,
        file_dir: &file_dir,
        module_dir: &module_dir,
        inline: Vec::new(),
        in_test: false,
        literals: Vec::new(),
        test_modules: Vec::new(),
        failure: None,
    };
    collector.visit_file(&file);
    if let Some(failure) = collector.failure {
        return Err(failure.into());
    }
    let literals: Vec<Literal> = collector.literals;
    let test_modules: Vec<PathBuf> = collector.test_modules;
    Ok(FileScan {
        path: path.to_path_buf(),
        relative,
        literals,
        test_modules,
    })
}

fn owns_directory(path: &Path) -> bool {
    let is_root_name: bool = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name: &str| matches!(name, "lib.rs" | "main.rs" | "mod.rs"));
    let parent: Option<&Path> = path.parent();
    let is_bin_root: bool = parent
        .and_then(Path::file_name)
        .is_some_and(|name| name == "bin")
        && parent
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "src");
    is_root_name || is_bin_root
}

fn relative_path(root: &Path, path: &Path) -> String {
    let relative: &Path = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .filter_map(|component: Component<'_>| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}

struct LiteralCollector<'a> {
    relative: &'a str,
    file_dir: &'a Path,
    module_dir: &'a Path,
    inline: Vec<String>,
    in_test: bool,
    literals: Vec<Literal>,
    test_modules: Vec<PathBuf>,
    failure: Option<ScanLimit>,
}

impl LiteralCollector<'_> {
    fn record(&mut self, text: String, span: Span) {
        if self.in_test || !text.contains("DR-") {
            return;
        }
        let start: LineColumn = span.start();
        self.literals.push(Literal {
            text,
            line: start.line,
            column: start.column,
        });
    }

    fn scan_tokens(&mut self, tokens: &TokenStream, depth: usize, span: Span) {
        if self.in_test || self.failure.is_some() {
            return;
        }
        if depth > MAX_TOKEN_DEPTH {
            self.failure = Some(ScanLimit::TokenDepth {
                path: self.relative.to_owned(),
                line: span.start().line,
                limit: MAX_TOKEN_DEPTH,
            });
            return;
        }
        for tree in tokens.clone() {
            match tree {
                TokenTree::Group(group) => {
                    if group.delimiter() == Delimiter::Bracket && is_doc_group(&group.stream()) {
                        continue;
                    }
                    self.scan_tokens(&group.stream(), depth + 1, group.span());
                }
                TokenTree::Literal(literal) => {
                    if let syn::Lit::Str(text) = syn::Lit::new(literal) {
                        self.record(text.value(), text.span());
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }

    fn exclude_module(&mut self, module: &syn::ItemMod) {
        let base: PathBuf = self.inline.iter().fold(
            self.module_dir.to_path_buf(),
            |dir: PathBuf, name: &String| dir.join(name),
        );
        if let Some(explicit) = path_attribute(&module.attrs) {
            let anchor: &Path = if self.inline.is_empty() {
                self.file_dir
            } else {
                &base
            };
            self.test_modules.push(anchor.join(explicit));
            return;
        }
        let name: String = module.ident.unraw().to_string();
        self.test_modules.push(base.join(format!("{name}.rs")));
        self.test_modules.push(base.join(name));
    }
}

impl<'ast> Visit<'ast> for LiteralCollector<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let gated: bool = self.in_test || is_test_only(&module.attrs);
        match &module.content {
            None => {
                if gated {
                    self.exclude_module(module);
                }
            }
            Some((_, items)) => {
                let outer: bool = self.in_test;
                self.in_test = gated;
                self.inline.push(module.ident.unraw().to_string());
                for item in items {
                    self.visit_item(item);
                }
                self.inline.pop();
                self.in_test = outer;
            }
        }
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if !is_test_only(&function.attrs) {
            syn::visit::visit_item_fn(self, function);
        }
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if !is_test_only(&function.attrs) {
            syn::visit::visit_impl_item_fn(self, function);
        }
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        if !is_test_only(&block.attrs) {
            syn::visit::visit_item_impl(self, block);
        }
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if self.in_test || attribute.path().is_ident("doc") {
            return;
        }
        match &attribute.meta {
            syn::Meta::List(list) => {
                self.scan_tokens(&list.tokens, 0, list.delimiter.span().join());
            }
            syn::Meta::Path(_) | syn::Meta::NameValue(_) => {
                syn::visit::visit_attribute(self, attribute);
            }
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.scan_tokens(&mac.tokens, 0, mac.delimiter.span().join());
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.record(literal.value(), literal.span());
    }
}

fn is_doc_group(tokens: &TokenStream) -> bool {
    matches!(tokens.clone().into_iter().next(), Some(TokenTree::Ident(ident)) if ident == "doc")
}

fn path_attribute(attributes: &[syn::Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute: &syn::Attribute| {
        let syn::Meta::NameValue(pair) = &attribute.meta else {
            return None;
        };
        if !pair.path.is_ident("path") {
            return None;
        }
        match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(text),
                ..
            }) => Some(text.value()),
            _ => None,
        }
    })
}

fn is_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute: &syn::Attribute| {
        let path: &syn::Path = attribute.path();
        if path
            .segments
            .last()
            .is_some_and(|segment: &syn::PathSegment| segment.ident == "test")
        {
            return true;
        }
        path.is_ident("cfg")
            && attribute
                .parse_args::<syn::Meta>()
                .is_ok_and(|predicate: syn::Meta| cfg_is_test_only(&predicate))
    })
}

fn cfg_is_test_only(predicate: &syn::Meta) -> bool {
    match predicate {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) => {
            let nested: Vec<syn::Meta> = list
                .parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
                .map(|items: Punctuated<syn::Meta, syn::Token![,]>| items.into_iter().collect())
                .unwrap_or_default();
            if list.path.is_ident("all") {
                nested.iter().any(cfg_is_test_only)
            } else if list.path.is_ident("any") {
                !nested.is_empty() && nested.iter().all(cfg_is_test_only)
            } else {
                false
            }
        }
        syn::Meta::NameValue(_) => false,
    }
}

fn codes_in(text: &str) -> Vec<(String, Option<String>)> {
    let bytes: &[u8] = text.as_bytes();
    let mut found: Vec<(String, Option<String>)> = Vec::new();
    let mut index: usize = 0;
    while let Some(offset) = text[index..].find("DR-") {
        let start: usize = index + offset;
        index = start + 3;
        let bounded_before: bool = start == 0 || !is_code_byte(bytes[start - 1]);
        let Some(end): Option<usize> = code_end(bytes, start) else {
            continue;
        };
        if !bounded_before {
            continue;
        }
        index = end;
        let code: String = text[start..end].to_owned();
        let message: Option<String> = if start == 0 {
            let rest: &str = text[end..].trim_start();
            let rest: &str = rest.strip_prefix(':').unwrap_or(rest);
            let normalized: String = normalize(rest);
            (!normalized.is_empty()).then_some(normalized)
        } else {
            Some(normalize(text))
        };
        found.push((code, message));
    }
    found
}

const fn is_code_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn code_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor: usize = start + 3;
    if !bytes.get(cursor).is_some_and(u8::is_ascii_uppercase) {
        return None;
    }
    while bytes
        .get(cursor)
        .is_some_and(|byte: &u8| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'-') {
        return None;
    }
    cursor += 1;
    let digits_end: usize = cursor + 4;
    if digits_end > bytes.len() || !bytes[cursor..digits_end].iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes
        .get(digits_end)
        .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return None;
    }
    Some(digits_end)
}

fn normalize(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = text.chars().peekable();
    let mut pending_space: bool = false;
    while let Some(current) = chars.next() {
        if current.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        match current {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push_str("{{");
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push_str("}}");
            }
            '{' => {
                let mut placeholder: String = String::new();
                let mut closed: bool = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        closed = true;
                        break;
                    }
                    placeholder.push(inner);
                }
                if closed {
                    out.push_str("{}");
                } else {
                    out.push('{');
                    out.push_str(&placeholder);
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn code_span(text: &str) -> String {
    let quoted: String = format!("{text:?}");
    let mut longest: usize = 0;
    let mut run: usize = 0;
    for character in quoted.chars() {
        if character == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence: String = "`".repeat(longest + 1);
    if longest == 0 {
        format!("{fence}{quoted}{fence}")
    } else {
        format!("{fence} {quoted} {fence}")
    }
}

fn site_list(sites: &[&Site]) -> String {
    sites
        .iter()
        .map(|site: &&Site| format!("`{}:{}`", site.path, site.line))
        .collect::<Vec<String>>()
        .join(", ")
}

pub(crate) fn render(census: &Census) -> String {
    let collisions: Vec<(&str, &CodeUse)> = census.collisions();
    let unregistered: Vec<(&str, &CodeUse)> = census.unregistered();
    let unemitted: Vec<&str> = census.unemitted();
    let mut lines: Vec<String> = vec![
        "# Error-code census".to_owned(),
        String::new(),
        "`cargo run -p xtask -- errcodes` writes this file, and `cargo run -p xtask -- errcodes --check` fails when it differs from a fresh scan. The scan reads every string literal, including format strings and attribute arguments, in the Rust sources under `crates/*/src/`. It skips comments, doc comments, `#[cfg(test)]` items, test functions, test-only module files and the explain registry in `crates/disrobe-cli/src/cli/explain/codes/`. A code at the start of a literal carries the text after its colon; a code elsewhere in a literal carries the whole literal; a literal holding only the code carries no message and is not compared. Format placeholders compare as `{}` and whitespace runs as one space.".to_owned(),
        String::new(),
        "| Measure | Count |".to_owned(),
        "| --- | ---: |".to_owned(),
        format!("| Scanned source files | {} |", census.scanned_files),
        format!("| Emission sites | {} |", census.site_count()),
        format!("| Sites carrying a message | {} |", census.message_site_count()),
        format!("| Distinct emitted codes | {} |", census.emitted.len()),
        format!("| Registered codes | {} |", census.registered.len()),
        format!("| Codes with two or more distinct messages | {} |", collisions.len()),
        format!("| Emitted codes missing from the registry | {} |", unregistered.len()),
        format!("| Registered codes no source emits | {} |", unemitted.len()),
        String::new(),
        format!("## Codes with two or more distinct messages ({})", collisions.len()),
    ];
    for (code, usage) in &collisions {
        lines.push(String::new());
        lines.push(format!("### `{code}`"));
        lines.push(String::new());
        for (message, sites) in &usage.messages {
            let sites: Vec<&Site> = sites.iter().collect();
            lines.push(format!("- {}: {}", code_span(message), site_list(&sites)));
        }
        if !usage.bare.is_empty() {
            let sites: Vec<&Site> = usage.bare.iter().collect();
            lines.push(format!("- no message: {}", site_list(&sites)));
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "## Emitted codes missing from the registry ({})",
        unregistered.len()
    ));
    lines.push(String::new());
    for (code, usage) in &unregistered {
        lines.push(format!("- `{code}`: {}", site_list(&usage.all_sites())));
    }
    lines.push(String::new());
    lines.push(format!(
        "## Registered codes no source emits ({})",
        unemitted.len()
    ));
    lines.push(String::new());
    for code in &unemitted {
        lines.push(format!("- `{code}`"));
    }
    let mut report: String = lines.join("\n");
    report.push('\n');
    report
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const REGISTRY_ENTRY: &str = "CodeEntry {\n    code: \"DR-DEMO-0001\",\n    title: \"demo\",\n    description: \"demo failure.\",\n    common_causes: &[],\n    common_fixes: &[],\n    crate_path: \"crates/demo/src/lib.rs\",\n},\n";

    fn fixture(library: &str) -> (tempfile::TempDir, Census) {
        let root: tempfile::TempDir = tempfile::tempdir().expect("temp dir");
        let registry: PathBuf = errdocs::registry_dir(root.path());
        fs::create_dir_all(&registry).expect("registry dir");
        fs::write(registry.join("demo.rs"), REGISTRY_ENTRY).expect("registry file");
        let source_dir: PathBuf = root.path().join("crates").join("demo").join("src");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::write(source_dir.join("lib.rs"), library).expect("library");
        let census: Census = scan(root.path(), &registry).expect("scan");
        (root, census)
    }

    #[test]
    fn errcodes_reports_a_code_with_two_messages_and_strict_mode_fails() {
        let (_root, census): (tempfile::TempDir, Census) = fixture(
            "fn a() -> String { format!(\"DR-DEMO-0001: cannot read {}\", 1) }\nfn b() -> &'static str { \"DR-DEMO-0001: cannot write output\" }\n",
        );
        let collided: Vec<&str> = census
            .collisions()
            .into_iter()
            .map(|(code, _): (&str, &CodeUse)| code)
            .collect();
        assert_eq!(collided, vec!["DR-DEMO-0001"]);
        assert!(census.unregistered().is_empty());
        let report: String = render(&census);
        assert!(report.contains("### `DR-DEMO-0001`"));
        assert!(report.contains("`\"cannot read {}\"`: `crates/demo/src/lib.rs:1`"));
        assert!(report.contains("`\"cannot write output\"`: `crates/demo/src/lib.rs:2`"));
        let failure: String = enforce_strict(&census)
            .expect_err("strict mode must reject a code with two messages")
            .to_string();
        assert!(failure.contains("DR-DEMO-0001"), "{failure}");
    }

    #[test]
    fn errcodes_reports_an_unregistered_code_and_strict_mode_fails() {
        let (_root, census): (tempfile::TempDir, Census) = fixture(
            "#[derive(Debug)]\nenum E {\n    #[error(\"DR-DEMO-0001: demo failure\")]\n    A,\n    #[error(\"DR-DEMO-0002: missing entry\")]\n    B,\n}\n",
        );
        assert!(census.collisions().is_empty());
        let unregistered: Vec<&str> = census
            .unregistered()
            .into_iter()
            .map(|(code, _): (&str, &CodeUse)| code)
            .collect();
        assert_eq!(unregistered, vec!["DR-DEMO-0002"]);
        assert!(render(&census).contains("- `DR-DEMO-0002`: `crates/demo/src/lib.rs:5`"));
        let failure: String = enforce_strict(&census)
            .expect_err("strict mode must reject an unregistered code")
            .to_string();
        assert!(failure.contains("DR-DEMO-0002"), "{failure}");
    }

    #[test]
    fn errcodes_identical_messages_at_two_sites_are_not_a_collision() {
        let (_root, census): (tempfile::TempDir, Census) = fixture(
            "fn a(e: u8) -> String { format!(\"DR-DEMO-0001: cannot read input: {e}\") }\nfn b(error: u8) -> String { format!(\"DR-DEMO-0001:  cannot read input: {error}\") }\n",
        );
        assert!(census.collisions().is_empty());
        assert_eq!(census.site_count(), 2);
        enforce_strict(&census).expect("identical messages pass strict mode");
    }

    #[test]
    fn errcodes_ignores_codes_in_comments_docs_and_tests() {
        let (_root, census): (tempfile::TempDir, Census) = fixture(
            "// DR-DEMO-0009: line comment\n/* DR-DEMO-0008: block comment */\n/// DR-DEMO-0007: doc comment\nfn a() -> &'static str { \"DR-DEMO-0001: demo failure\" }\n#[cfg(test)]\nmod tests {\n    fn t() -> &'static str { \"DR-DEMO-0006: only in a test\" }\n}\n#[cfg(test)]\nmod more;\n",
        );
        let codes: Vec<&String> = census.emitted.keys().collect();
        assert_eq!(codes, vec!["DR-DEMO-0001"]);
        enforce_strict(&census).expect("comments and tests emit nothing");
    }

    #[test]
    fn errcodes_skips_test_module_files() {
        let root: tempfile::TempDir = tempfile::tempdir().expect("temp dir");
        let registry: PathBuf = errdocs::registry_dir(root.path());
        fs::create_dir_all(&registry).expect("registry dir");
        fs::write(registry.join("demo.rs"), REGISTRY_ENTRY).expect("registry file");
        let source_dir: PathBuf = root.path().join("crates").join("demo").join("src");
        fs::create_dir_all(source_dir.join("tests")).expect("source dir");
        fs::write(
            source_dir.join("lib.rs"),
            "#[cfg(all(test, feature = \"x\"))]\nmod tests;\n",
        )
        .expect("library");
        fs::write(
            source_dir.join("tests").join("mod.rs"),
            "fn t() -> &'static str { \"DR-DEMO-0005: test only\" }\n",
        )
        .expect("test module");
        let census: Census = scan(root.path(), &registry).expect("scan");
        assert!(census.emitted.is_empty());
        assert_eq!(census.scanned_files, 1);
    }

    #[test]
    fn errcodes_message_extraction_matches_the_code_grammar() {
        assert_eq!(
            codes_in("DR-CLI-0444: cannot write {}: {e}"),
            vec![(
                "DR-CLI-0444".to_owned(),
                Some("cannot write {}: {}".to_owned())
            )]
        );
        assert_eq!(
            codes_in("DR-MCP-0652"),
            vec![("DR-MCP-0652".to_owned(), None)]
        );
        assert!(codes_in("DR-JVM-CORE-0001 DR-SEC-AWS-AK XDR-CLI-0001 DR-CLI-00012").is_empty());
        assert_eq!(
            codes_in("see DR-CLI-0001 {{here}}"),
            vec![(
                "DR-CLI-0001".to_owned(),
                Some("see DR-CLI-0001 {{here}}".to_owned())
            )]
        );
    }
}
