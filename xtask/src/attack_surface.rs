use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

const MAX_SECURITY_MD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CARGO_TOML_BYTES: u64 = 256 * 1024;
const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;

const UNTRUSTED_PARSERS_HEADING: &str =
    "**Untrusted-input parsers (format / container / bytecode):**";
const SUBPROCESS_HEADING: &str = "**Subprocess-capable code**";
const NETWORK_HEADING: &str = "**Network-capable code**";
const CRYPTOGRAPHY_HEADING: &str = "## Cryptography";
const CFG_TEST_ATTR: &str = "#[cfg(test)]";
const COMMAND_NEW_CALL: &str = "Command::new(";
const NETWORK_DEP_NAMES: &[&str] = &["reqwest", "axum", "hyper", "tonic"];

struct NonParserCrate {
    package_name: &'static str,
    rationale: &'static str,
}

const NON_PARSER_ALLOWLIST: &[NonParserCrate] = &[
    NonParserCrate {
        package_name: "disrobe-bytes",
        rationale: "generic bounds-checked byte-reader primitives shared by the parsers, not a format-specific parser itself",
    },
    NonParserCrate {
        package_name: "disrobe-capabilities",
        rationale: "rule engine evaluated over already-lifted disasm IR, does not parse raw untrusted bytes",
    },
    NonParserCrate {
        package_name: "disrobe-cli",
        rationale: "command-line entry point; dispatches into the parser crates rather than parsing formats itself",
    },
    NonParserCrate {
        package_name: "disrobe-core",
        rationale: "shared traits, error types, and pass-dispatch primitives with no format-specific parsing",
    },
    NonParserCrate {
        package_name: "disrobe-emit",
        rationale: "output-side pretty-printer for recovered source, operates on already-recovered ASTs",
    },
    NonParserCrate {
        package_name: "disrobe-irsummary",
        rationale: "summarizes the already-lifted Mir-rung IR, downstream of the format parsers",
    },
    NonParserCrate {
        package_name: "disrobe-llm-metadata",
        rationale: "output-side metadata envelope for the --llm bundle, not an input parser",
    },
    NonParserCrate {
        package_name: "disrobe-mba",
        rationale: "bounded symbolic simplifier over bitvector expressions, no file or format parsing",
    },
    NonParserCrate {
        package_name: "disrobe-mcp",
        rationale: "MCP stdio tool surface over already-produced envelopes, not a hostile binary-format parser",
    },
    NonParserCrate {
        package_name: "disrobe-playground",
        rationale: "test/bench-only accuracy harness, not shipped parsing surface",
    },
    NonParserCrate {
        package_name: "disrobe-plugin-host",
        rationale: "sandboxed WASM execution runtime; the plugin trust model is documented separately in SECURITY.md",
    },
    NonParserCrate {
        package_name: "disrobe-plugin-loader",
        rationale: "signed WASM-component loader; the plugin trust model is documented separately in SECURITY.md",
    },
    NonParserCrate {
        package_name: "disrobe-prowl",
        rationale: "OSINT/IOC harvester tool, already documented in the Network-capable code table instead",
    },
    NonParserCrate {
        package_name: "disrobe-python",
        rationale: "pyo3 bindings that wrap the parser crates, not a parser itself",
    },
    NonParserCrate {
        package_name: "disrobe-query",
        rationale: "typed query evaluator over an already-loaded .dr envelope or IR module",
    },
    NonParserCrate {
        package_name: "disrobe-rules",
        rationale: "loader for disrobe's own serde-validated rewrite-rule DSL, not an adversarial-input format",
    },
    NonParserCrate {
        package_name: "disrobe-semdiff",
        rationale: "semantic diff over the already-lifted Mir-rung IR, downstream of the format parsers",
    },
    NonParserCrate {
        package_name: "disrobe-taint",
        rationale: "dataflow analysis over the already-lifted Mir-rung IR, downstream of the format parsers",
    },
    NonParserCrate {
        package_name: "disrobe-vulnmatch",
        rationale: "reachability and rule-match analysis over the already-recovered call graph and taint via read-only adapters, not a raw-input parser",
    },
    NonParserCrate {
        package_name: "disrobe-transcode",
        rationale: "rewrites disrobe's own already-parsed .dr envelope, not the original untrusted input",
    },
    NonParserCrate {
        package_name: "disrobe-validator",
        rationale: "test/bench-only corpus harness, not shipped parsing surface",
    },
    NonParserCrate {
        package_name: "disrobe-wasm",
        rationale: "C-ABI facade over the parser crates for the browser playground, not a parser itself",
    },
    NonParserCrate {
        package_name: "xtask",
        rationale: "repo automation, not part of the crates/ tree walked by this check but kept explicit for clarity",
    },
];

struct CrateManifest {
    dir_name: String,
    package_name: String,
    dependencies: BTreeSet<String>,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let security_path: PathBuf = root.join("SECURITY.md");
    let security_md: String = read_text_bounded(&security_path, MAX_SECURITY_MD_BYTES)
        .wrap_err_with(|| format!("reading {}", security_path.display()))?;

    let manifests: Vec<CrateManifest> = read_crate_manifests(root)?;
    let mut drift: Vec<String> = Vec::new();

    check_crate_inventory(&manifests, &security_md, &mut drift)?;
    check_subprocess_inventory(root, &security_md, &mut drift)?;
    check_network_inventory(&manifests, &security_md, &mut drift)?;

    if drift.is_empty() {
        println!(
            "xtask regen: attack-surface inventory cross-check ok ({} crate(s) classified, subprocess call sites and network dependencies match SECURITY.md)",
            manifests.len()
        );
        Ok(())
    } else {
        bail!(
            "SECURITY.md's attack surface inventory drifted from the real workspace; update the doc by hand:\n  {}",
            drift.join("\n  ")
        )
    }
}

fn read_crate_manifests(root: &Path) -> Result<Vec<CrateManifest>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(&crates_dir)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .collect::<std::result::Result<Vec<walkdir::DirEntry>, walkdir::Error>>()
        .wrap_err_with(|| format!("walking {}", crates_dir.display()))?
        .into_iter()
        .filter(|entry: &walkdir::DirEntry| entry.file_type().is_dir())
        .map(|entry: walkdir::DirEntry| entry.path().to_path_buf())
        .collect();
    dirs.sort();

    let mut manifests: Vec<CrateManifest> = Vec::with_capacity(dirs.len());
    for dir in dirs {
        let manifest_path: PathBuf = dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let raw: String = read_text_bounded(&manifest_path, MAX_CARGO_TOML_BYTES)
            .wrap_err_with(|| format!("reading {}", manifest_path.display()))?;
        let parsed: toml::Table = raw
            .parse::<toml::Table>()
            .wrap_err_with(|| format!("parsing {}", manifest_path.display()))?;
        let package_name: String = parsed
            .get("package")
            .and_then(|package: &toml::Value| package.get("name"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| eyre!("{} has no [package].name", manifest_path.display()))?
            .to_owned();
        let dependencies: BTreeSet<String> = parsed
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .map(|table: &toml::map::Map<String, toml::Value>| table.keys().cloned().collect())
            .unwrap_or_default();
        let dir_name: String = dir
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| eyre!("non-utf8 crate directory {}", dir.display()))?
            .to_owned();
        manifests.push(CrateManifest {
            dir_name,
            package_name,
            dependencies,
        });
    }
    Ok(manifests)
}

fn extract_section<'doc>(
    markdown: &'doc str,
    start_marker: &str,
    end_marker: &str,
) -> Result<&'doc str> {
    let start: usize = markdown
        .find(start_marker)
        .ok_or_else(|| eyre!("SECURITY.md is missing the heading `{start_marker}`"))?;
    let after_start: usize = start + start_marker.len();
    let end_offset: usize = markdown[after_start..].find(end_marker).ok_or_else(|| {
        eyre!("SECURITY.md is missing the heading `{end_marker}` after `{start_marker}`")
    })?;
    Ok(&markdown[after_start..after_start + end_offset])
}

fn backtick_tokens(section: &str) -> BTreeSet<String> {
    section
        .split('`')
        .enumerate()
        .filter(|(index, _): &(usize, &str)| index % 2 == 1)
        .map(|(_, token): (usize, &str)| token.to_owned())
        .collect()
}

fn table_row_backtick_tokens(section: &str) -> BTreeSet<String> {
    let rows: String = section
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with('|'))
        .collect::<Vec<&str>>()
        .join("\n");
    backtick_tokens(&rows)
}

fn check_crate_inventory(
    manifests: &[CrateManifest],
    security_md: &str,
    drift: &mut Vec<String>,
) -> Result<()> {
    let section: &str =
        extract_section(security_md, UNTRUSTED_PARSERS_HEADING, SUBPROCESS_HEADING)?;
    let mentioned: BTreeSet<String> = table_row_backtick_tokens(section);
    let allowlisted: BTreeSet<&str> = NON_PARSER_ALLOWLIST
        .iter()
        .map(|entry: &NonParserCrate| entry.package_name)
        .collect();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for manifest in manifests {
        seen.insert(manifest.package_name.clone());
        if mentioned.contains(&manifest.package_name)
            || allowlisted.contains(manifest.package_name.as_str())
        {
            continue;
        }
        drift.push(format!(
            "crates/{} (package `{}`) is neither mentioned in SECURITY.md's Untrusted-input parsers table nor allowlisted as a non-parser crate in xtask/src/attack_surface.rs; classify it explicitly",
            manifest.dir_name, manifest.package_name
        ));
    }
    for entry in NON_PARSER_ALLOWLIST {
        if entry.package_name != "xtask" && !seen.contains(entry.package_name) {
            drift.push(format!(
                "xtask/src/attack_surface.rs allowlists `{}` ({}) but no such crate exists under crates/ anymore; remove the stale entry",
                entry.package_name, entry.rationale
            ));
        }
    }
    Ok(())
}

fn check_network_inventory(
    manifests: &[CrateManifest],
    security_md: &str,
    drift: &mut Vec<String>,
) -> Result<()> {
    let section: &str = extract_section(security_md, NETWORK_HEADING, CRYPTOGRAPHY_HEADING)?;
    let documented: BTreeSet<String> = table_row_backtick_tokens(section)
        .into_iter()
        .filter(|token: &String| token.starts_with("disrobe-"))
        .collect();

    for manifest in manifests {
        let linked: Vec<&str> = NETWORK_DEP_NAMES
            .iter()
            .copied()
            .filter(|dep: &&str| manifest.dependencies.contains(*dep))
            .collect();
        if linked.is_empty() || documented.contains(&manifest.package_name) {
            continue;
        }
        drift.push(format!(
            "crates/{} (package `{}`) links {} but is not listed in SECURITY.md's Network-capable code table",
            manifest.dir_name,
            manifest.package_name,
            linked.join(", ")
        ));
    }
    for name in &documented {
        if !manifests
            .iter()
            .any(|manifest: &CrateManifest| &manifest.package_name == name)
        {
            drift.push(format!(
                "SECURITY.md's Network-capable code table lists `{name}`, but no such crate exists under crates/ anymore"
            ));
        }
    }
    Ok(())
}

fn check_subprocess_inventory(
    root: &Path,
    security_md: &str,
    drift: &mut Vec<String>,
) -> Result<()> {
    let section: &str = extract_section(security_md, SUBPROCESS_HEADING, NETWORK_HEADING)?;
    let documented: BTreeSet<String> = documented_subprocess_paths(section);

    let real: BTreeSet<String> = find_real_subprocess_sites(root)?;

    for path in real.difference(&documented) {
        drift.push(format!(
            "{path} calls `Command::new` outside any #[cfg(test)] scope but is not listed in SECURITY.md's Subprocess-capable code table"
        ));
    }
    for path in documented.difference(&real) {
        drift.push(format!(
            "SECURITY.md's Subprocess-capable code table lists `{path}`, but no non-test `Command::new` call site was found there anymore"
        ));
    }
    Ok(())
}

fn documented_subprocess_paths(section: &str) -> BTreeSet<String> {
    table_row_backtick_tokens(section)
        .into_iter()
        .filter(|token: &String| {
            token.starts_with("crates/")
                && Path::new(token)
                    .extension()
                    .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("rs"))
        })
        .collect()
}

fn find_real_subprocess_sites(root: &Path) -> Result<BTreeSet<String>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut sites: BTreeSet<String> = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&crates_dir) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", crates_dir.display()))?;
        let path: &Path = dirent.path();
        if !path.is_file() || path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
            continue;
        }
        if !is_under_crate_src(path, &crates_dir) {
            continue;
        }
        let source: String = read_text_bounded(path, MAX_SOURCE_FILE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        if !has_real_command_new(&source) {
            continue;
        }
        let relative: &Path = path.strip_prefix(root).wrap_err_with(|| {
            format!(
                "stripping {} prefix from {}",
                root.display(),
                path.display()
            )
        })?;
        sites.insert(to_forward_slash(relative));
    }
    Ok(sites)
}

fn is_under_crate_src(path: &Path, crates_dir: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(crates_dir) else {
        return false;
    };
    let mut components: std::path::Components<'_> = relative.components();
    if components.next().is_none() {
        return false;
    }
    matches!(
        components.next(),
        Some(std::path::Component::Normal(name)) if name == "src"
    )
}

fn to_forward_slash(path: &Path) -> String {
    path.components()
        .filter_map(|component: std::path::Component<'_>| component.as_os_str().to_str())
        .collect::<Vec<&str>>()
        .join("/")
}

fn has_real_command_new(source: &str) -> bool {
    let spans: Vec<(usize, usize)> = cfg_test_spans(source);
    let mut search_from: usize = 0;
    while let Some(relative) = source[search_from..].find(COMMAND_NEW_CALL) {
        let offset: usize = search_from + relative;
        let inside_test_span: bool = spans
            .iter()
            .any(|(start, end): &(usize, usize)| offset >= *start && offset < *end);
        if !inside_test_span {
            return true;
        }
        search_from = offset + COMMAND_NEW_CALL.len();
    }
    false
}

fn cfg_test_spans(source: &str) -> Vec<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut search_from: usize = 0;
    while let Some(relative) = source[search_from..].find(CFG_TEST_ATTR) {
        let attr_start: usize = search_from + relative;
        let after_attr: usize = attr_start + CFG_TEST_ATTR.len();
        match find_item_body_open(bytes, after_attr) {
            Some(open) => match matching_brace(bytes, open) {
                Some(close) => {
                    spans.push((attr_start, close + 1));
                    search_from = close + 1;
                }
                None => search_from = after_attr,
            },
            None => search_from = after_attr,
        }
    }
    spans
}

fn find_item_body_open(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index: usize = from;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => return Some(index),
            b';' => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

#[derive(Clone, Copy)]
enum LexState {
    Normal,
    LineComment,
    BlockComment { depth: u32 },
    Str,
    StrEscape,
    RawStr { hashes: u32 },
    Char,
    CharEscape,
}

fn matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth: i64 = 0;
    let mut state: LexState = LexState::Normal;
    let mut index: usize = open;
    while index < bytes.len() {
        let byte: u8 = bytes[index];
        let mut advance: usize = 1;
        state = match state {
            LexState::Normal => match byte {
                b'{' => {
                    depth += 1;
                    LexState::Normal
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                    LexState::Normal
                }
                b'"' => LexState::Str,
                b'\'' if bytes.get(index + 1) == Some(&b'\\') => LexState::Char,
                b'\'' if bytes.get(index + 2) == Some(&b'\'') => LexState::Char,
                b'/' if bytes.get(index + 1) == Some(&b'/') => LexState::LineComment,
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    advance = 2;
                    LexState::BlockComment { depth: 1 }
                }
                _ => match raw_string_prefix_len(bytes, index) {
                    Some((prefix_len, hashes)) => {
                        advance = prefix_len;
                        LexState::RawStr { hashes }
                    }
                    None => LexState::Normal,
                },
            },
            LexState::LineComment => {
                if byte == b'\n' {
                    LexState::Normal
                } else {
                    LexState::LineComment
                }
            }
            LexState::BlockComment {
                depth: comment_depth,
            } => {
                if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    advance = 2;
                    LexState::BlockComment {
                        depth: comment_depth + 1,
                    }
                } else if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    advance = 2;
                    if comment_depth <= 1 {
                        LexState::Normal
                    } else {
                        LexState::BlockComment {
                            depth: comment_depth - 1,
                        }
                    }
                } else {
                    LexState::BlockComment {
                        depth: comment_depth,
                    }
                }
            }
            LexState::Str => match byte {
                b'\\' => LexState::StrEscape,
                b'"' => LexState::Normal,
                _ => LexState::Str,
            },
            LexState::StrEscape => LexState::Str,
            LexState::RawStr { hashes } => {
                if byte == b'"' && has_hash_run(bytes, index + 1, hashes) {
                    advance = 1 + hashes as usize;
                    LexState::Normal
                } else {
                    LexState::RawStr { hashes }
                }
            }
            LexState::Char => match byte {
                b'\\' => LexState::CharEscape,
                b'\'' => LexState::Normal,
                _ => LexState::Char,
            },
            LexState::CharEscape => LexState::Char,
        };
        index += advance;
    }
    None
}

fn raw_string_prefix_len(bytes: &[u8], index: usize) -> Option<(usize, u32)> {
    let mut cursor: usize = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let mut hashes: u32 = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'"') {
        Some((cursor - index + 1, hashes))
    } else {
        None
    }
}

fn has_hash_run(bytes: &[u8], from: usize, hashes: u32) -> bool {
    (0..hashes).all(|offset: u32| bytes.get(from + offset as usize) == Some(&b'#'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(package_name: &str, dir_name: &str, deps: &[&str]) -> CrateManifest {
        CrateManifest {
            dir_name: dir_name.to_owned(),
            package_name: package_name.to_owned(),
            dependencies: deps.iter().map(|dep: &&str| (*dep).to_owned()).collect(),
        }
    }

    fn allowlisted_manifests() -> Vec<CrateManifest> {
        NON_PARSER_ALLOWLIST
            .iter()
            .filter(|entry: &&NonParserCrate| entry.package_name != "xtask")
            .map(|entry: &NonParserCrate| manifest(entry.package_name, entry.package_name, &[]))
            .collect()
    }

    #[test]
    fn extract_section_slices_between_markers() -> core::result::Result<(), String> {
        let doc: &str = "before\n**A**\nmiddle text\n**B**\nafter";
        let section: &str = extract_section(doc, "**A**", "**B**").map_err(|e| e.to_string())?;
        assert_eq!(section, "\nmiddle text\n");
        Ok(())
    }

    #[test]
    fn extract_section_errors_on_missing_marker() {
        let doc: &str = "no headings here";
        assert!(extract_section(doc, "**A**", "**B**").is_err());
    }

    #[test]
    fn backtick_tokens_extracts_only_wrapped_text() {
        let section: &str = "| Family | `disrobe-binfmt` (containers), `disrobe-pass-native` |";
        let tokens: BTreeSet<String> = backtick_tokens(section);
        assert!(tokens.contains("disrobe-binfmt"));
        assert!(tokens.contains("disrobe-pass-native"));
        assert!(!tokens.contains("Family"));
        assert!(!tokens.contains("(containers)"));
    }

    #[test]
    fn crate_inventory_flags_unclassified_new_crate() -> core::result::Result<(), String> {
        let mut manifests: Vec<CrateManifest> = allowlisted_manifests();
        manifests.push(manifest(
            "disrobe-pass-newformat",
            "disrobe-pass-newformat",
            &[],
        ));
        let security_md: String = format!(
            "{UNTRUSTED_PARSERS_HEADING}\n| Family | Crates |\n|---|---|\n| Existing | `disrobe-pass-native` |\n\n{SUBPROCESS_HEADING}\n\n{NETWORK_HEADING}\n\n{CRYPTOGRAPHY_HEADING}\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_crate_inventory(&manifests, &security_md, &mut drift).map_err(|e| e.to_string())?;
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("disrobe-pass-newformat"));
        Ok(())
    }

    #[test]
    fn crate_inventory_accepts_mentioned_and_allowlisted_crates() -> core::result::Result<(), String>
    {
        let mut manifests: Vec<CrateManifest> = allowlisted_manifests();
        manifests.push(manifest("disrobe-pass-native", "disrobe-pass-native", &[]));
        let security_md: String = format!(
            "{UNTRUSTED_PARSERS_HEADING}\n| Family | Crates |\n|---|---|\n| Native | `disrobe-pass-native` |\n\n{SUBPROCESS_HEADING}\n\n{NETWORK_HEADING}\n\n{CRYPTOGRAPHY_HEADING}\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_crate_inventory(&manifests, &security_md, &mut drift).map_err(|e| e.to_string())?;
        assert!(drift.is_empty(), "drift: {drift:?}");
        Ok(())
    }

    #[test]
    fn network_inventory_flags_new_linker_and_stale_doc_entry() -> core::result::Result<(), String>
    {
        let manifests: Vec<CrateManifest> = vec![
            manifest("disrobe-pass-native", "disrobe-pass-native", &["reqwest"]),
            manifest("disrobe-cli", "disrobe-cli", &["reqwest"]),
        ];
        let security_md: String = format!(
            "{NETWORK_HEADING}\n| Direction | Crate | Path |\n|---|---|---|\n| Outbound | `disrobe-cli` | text |\n| Outbound | `disrobe-prowl` | text |\n\n{CRYPTOGRAPHY_HEADING}\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_network_inventory(&manifests, &security_md, &mut drift).map_err(|e| e.to_string())?;
        assert_eq!(drift.len(), 2);
        assert!(
            drift
                .iter()
                .any(|line: &String| line.contains("disrobe-pass-native"))
        );
        assert!(
            drift
                .iter()
                .any(|line: &String| line.contains("disrobe-prowl"))
        );
        Ok(())
    }

    #[test]
    fn network_inventory_accepts_documented_linker() -> core::result::Result<(), String> {
        let manifests: Vec<CrateManifest> =
            vec![manifest("disrobe-cli", "disrobe-cli", &["reqwest", "axum"])];
        let security_md: String = format!(
            "{NETWORK_HEADING}\n| Direction | Crate | Path |\n|---|---|---|\n| Outbound | `disrobe-cli` | text |\n\n{CRYPTOGRAPHY_HEADING}\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_network_inventory(&manifests, &security_md, &mut drift).map_err(|e| e.to_string())?;
        assert!(drift.is_empty(), "drift: {drift:?}");
        Ok(())
    }

    #[test]
    fn documented_subprocess_paths_ignores_bare_filenames_in_description_cells() {
        let section: &str = "\n| Path | What it invokes |\n|---|---|\n| `crates/disrobe-binfmt/src/external_wrap.rs`, `crates/disrobe-core/src/format/process.rs` | `process.rs` is the native-only analog of `external_wrap.rs`. |\n\nProse below the table also mentions `crates/disrobe-pass-native/src/pseudo_c.rs` in backticks, but it must not count as documented since it is not inside a table row.\n";
        let paths: BTreeSet<String> = documented_subprocess_paths(section);
        assert!(paths.contains("crates/disrobe-binfmt/src/external_wrap.rs"));
        assert!(paths.contains("crates/disrobe-core/src/format/process.rs"));
        assert!(!paths.contains("process.rs"));
        assert!(!paths.contains("external_wrap.rs"));
        assert!(!paths.contains("crates/disrobe-pass-native/src/pseudo_c.rs"));
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn cfg_test_spans_covers_trailing_test_module_only() {
        let source: &str = "fn real() {\n    Command::new(\"x\");\n}\n\n#[cfg(test)]\nmod tests {\n    fn helper() {\n        Command::new(\"y\");\n    }\n}\n";
        assert!(has_real_command_new(source));
    }

    #[test]
    fn cfg_test_spans_excludes_purely_test_only_call() {
        let source: &str = "fn setup() {\n    let x = 1;\n}\n\n#[cfg(test)]\nmod tests {\n    fn helper() {\n        Command::new(\"y\");\n    }\n}\n";
        assert!(!has_real_command_new(source));
    }

    #[test]
    fn cfg_test_spans_survives_leading_cfg_test_helper_before_real_code() {
        let source: &str = "#[cfg(test)]\nfn lock() -> u8 {\n    1\n}\n\nfn real() {\n    Command::new(\"z\");\n}\n";
        assert!(has_real_command_new(source));
    }

    #[test]
    fn cfg_test_spans_ignores_lifetimes_and_raw_strings_inside_body() {
        let source: &str = "#[cfg(test)]\nmod tests {\n    fn helper<'a>(x: &'a str) -> &'a str {\n        let script = r#\"{ \"nested\": true }\"#;\n        let _ = script;\n        Command::new(x);\n        x\n    }\n}\n";
        assert!(!has_real_command_new(source));
    }

    #[test]
    fn cfg_test_spans_bareword_attribute_without_body_is_skipped() {
        let source: &str = "#[cfg(test)]\nuse std::process::Command;\n\nfn real() {\n    Command::new(\"z\");\n}\n";
        assert!(has_real_command_new(source));
    }

    #[test]
    fn to_forward_slash_normalizes_components() {
        let path: PathBuf = PathBuf::from("crates").join("disrobe-cli").join("src");
        assert_eq!(to_forward_slash(&path), "crates/disrobe-cli/src");
    }
}
