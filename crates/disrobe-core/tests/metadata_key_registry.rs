#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use regex::Regex;

use disrobe_core::chain::metadata_keys::{RegisteredKey, registered_keys};

const KEYED_MAP_OPERATIONS: [&str; 40] = [
    "append(",
    "clear(",
    "clone(",
    "clone_from(",
    "contains_key(",
    "entry(",
    "extend(",
    "extract_if(",
    "get(",
    "get_key_value(",
    "get_mut(",
    "get_disjoint_mut(",
    "get_many_mut(",
    "insert(",
    "into_iter(",
    "into_keys(",
    "into_values(",
    "is_empty(",
    "iter(",
    "iter_mut(",
    "keys(",
    "last_entry(",
    "last_key_value(",
    "len(",
    "lower_bound(",
    "lower_bound_mut(",
    "range(",
    "range_mut(",
    "pop_first(",
    "pop_last(",
    "remove(",
    "remove_entry(",
    "retain(",
    "first_entry(",
    "first_key_value(",
    "split_off(",
    "upper_bound(",
    "upper_bound_mut(",
    "values(",
    "values_mut(",
];

const TYPED_METADATA_ACCESSORS: [&str; 10] = [
    "get_string",
    "set_string",
    "get_comma_list",
    "set_comma_list",
    "get_integer",
    "set_integer",
    "get_boolean",
    "set_boolean",
    "get_json",
    "set_json",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(
            || panic!("disrobe-core manifest must be nested under the repository root"),
            Path::to_path_buf,
        )
}

fn rust_source_paths(root: &Path) -> Vec<PathBuf> {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut sources: Vec<PathBuf> = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries: std::fs::ReadDir =
            std::fs::read_dir(&directory).unwrap_or_else(|error: std::io::Error| {
                panic!("failed to read {}: {error}", directory.display())
            });
        for entry in entries {
            let entry: std::fs::DirEntry = entry.unwrap_or_else(|error: std::io::Error| {
                panic!("failed to read directory entry: {error}")
            });
            let file_type: std::fs::FileType =
                entry.file_type().unwrap_or_else(|error: std::io::Error| {
                    panic!("failed to read {} type: {error}", entry.path().display())
                });
            let path: PathBuf = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                sources.push(path);
            }
        }
    }
    sources.sort_unstable();
    sources
}

fn skip_non_code(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index..index.saturating_add(2)) == Some(b"//") {
        return Some(
            bytes[index.saturating_add(2)..]
                .iter()
                .position(|byte: &u8| *byte == b'\n')
                .map_or(bytes.len(), |offset: usize| {
                    index.saturating_add(3).saturating_add(offset)
                }),
        );
    }
    if bytes.get(index..index.saturating_add(2)) == Some(b"/*") {
        let mut cursor: usize = index.saturating_add(2);
        let mut depth: usize = 1;
        while cursor < bytes.len() && depth > 0 {
            if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"/*") {
                depth = depth.saturating_add(1);
                cursor = cursor.saturating_add(2);
            } else if bytes.get(cursor..cursor.saturating_add(2)) == Some(b"*/") {
                depth = depth.saturating_sub(1);
                cursor = cursor.saturating_add(2);
            } else {
                cursor = cursor.saturating_add(1);
            }
        }
        return Some(cursor);
    }
    if bytes.get(index) == Some(&b'"') {
        let mut cursor: usize = index.saturating_add(1);
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => cursor = cursor.saturating_add(2),
                b'"' => return Some(cursor.saturating_add(1)),
                _ => cursor = cursor.saturating_add(1),
            }
        }
        return Some(bytes.len());
    }
    if bytes.get(index) == Some(&b'r') {
        let mut quote: usize = index.saturating_add(1);
        while bytes.get(quote) == Some(&b'#') {
            quote = quote.saturating_add(1);
        }
        if bytes.get(quote) == Some(&b'"') {
            let hashes: usize = quote.saturating_sub(index).saturating_sub(1);
            let mut cursor: usize = quote.saturating_add(1);
            while cursor < bytes.len() {
                if bytes[cursor] == b'"'
                    && bytes.get(cursor.saturating_add(1)..cursor.saturating_add(1 + hashes))
                        == bytes.get(index.saturating_add(1)..quote)
                {
                    return Some(cursor.saturating_add(1 + hashes));
                }
                cursor = cursor.saturating_add(1);
            }
            return Some(bytes.len());
        }
    }
    if bytes.get(index) == Some(&b'\'') {
        let close: usize = if bytes.get(index.saturating_add(1)) == Some(&b'\\') {
            index.saturating_add(3)
        } else {
            index.saturating_add(2)
        };
        if bytes.get(close) == Some(&b'\'') {
            return Some(close.saturating_add(1));
        }
    }
    None
}

fn code_only(source: &str) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut output: Vec<u8> = bytes.to_vec();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        if let Some(next) = skip_non_code(bytes, cursor) {
            output[cursor..next].fill(b' ');
            cursor = next;
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    String::from_utf8(output).expect("source masking preserves UTF-8 boundaries")
}

fn cfg_test_item_end(source: &str, start: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut cursor: usize = start;
    while cursor < bytes.len() {
        if let Some(next) = skip_non_code(bytes, cursor) {
            cursor = next;
            continue;
        }
        if bytes[cursor] == b';' {
            return cursor.saturating_add(1);
        }
        if bytes[cursor] == b'{' {
            let mut depth: usize = 1;
            cursor = cursor.saturating_add(1);
            while cursor < bytes.len() && depth > 0 {
                if let Some(next) = skip_non_code(bytes, cursor) {
                    cursor = next;
                    continue;
                }
                match bytes[cursor] {
                    b'{' => depth = depth.saturating_add(1),
                    b'}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                cursor = cursor.saturating_add(1);
            }
            return cursor;
        }
        cursor = cursor.saturating_add(1);
    }
    bytes.len()
}

fn matching_delimiter(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut cursor: usize = start.saturating_add(1);
    let mut depth: usize = 1;
    while cursor < bytes.len() {
        if let Some(next) = skip_non_code(bytes, cursor) {
            cursor = next;
            continue;
        }
        if bytes[cursor] == open {
            depth = depth.saturating_add(1);
        } else if bytes[cursor] == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(cursor);
            }
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn cfg_expression_requires_test(expression: &str) -> bool {
    let compact: String = expression
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect();
    if compact == "test" {
        return true;
    }
    for entry in [("all", false), ("any", true)] {
        let (operator, require_all): (&str, bool) = entry;
        let prefix: String = format!("{operator}(");
        if !compact.starts_with(&prefix) || !compact.ends_with(')') {
            continue;
        }
        let inner: &str = &compact[prefix.len()..compact.len().saturating_sub(1)];
        let mut arguments: Vec<&str> = Vec::new();
        let mut depth: usize = 0;
        let mut start: usize = 0;
        for (index, byte) in inner.bytes().enumerate() {
            match byte {
                b'(' => depth = depth.saturating_add(1),
                b')' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => {
                    arguments.push(&inner[start..index]);
                    start = index.saturating_add(1);
                }
                _ => {}
            }
        }
        arguments.push(&inner[start..]);
        return if require_all {
            !arguments.is_empty()
                && arguments
                    .iter()
                    .all(|argument: &&str| cfg_expression_requires_test(argument))
        } else {
            arguments
                .iter()
                .any(|argument: &&str| cfg_expression_requires_test(argument))
        };
    }
    false
}

fn next_test_cfg_attribute(source: &str, start: usize) -> Option<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut cursor: usize = start;
    while cursor < bytes.len() {
        if let Some(next) = skip_non_code(bytes, cursor) {
            cursor = next;
            continue;
        }
        if bytes[cursor] != b'#' {
            cursor = cursor.saturating_add(1);
            continue;
        }
        let attribute_start: usize = cursor;
        cursor = cursor.saturating_add(1);
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) != Some(&b'[') {
            continue;
        }
        cursor = cursor.saturating_add(1);
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor..cursor.saturating_add(3)) != Some(b"cfg") {
            continue;
        }
        cursor = cursor.saturating_add(3);
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) != Some(&b'(') {
            continue;
        }
        let expression_start: usize = cursor.saturating_add(1);
        let close_parenthesis: usize = matching_delimiter(bytes, cursor, b'(', b')')?;
        cursor = close_parenthesis.saturating_add(1);
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) != Some(&b']') {
            continue;
        }
        if cfg_expression_requires_test(&source[expression_start..close_parenthesis]) {
            return Some((attribute_start, cursor.saturating_add(1)));
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn without_test_cfg_items(source: &str) -> String {
    let mut output: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    while let Some((marker, attribute_end)) = next_test_cfg_attribute(source, cursor) {
        output.push_str(&source[cursor..marker]);
        cursor = cfg_test_item_end(source, attribute_end);
    }
    output.push_str(&source[cursor..]);
    output
}

#[derive(Debug, Default, PartialEq, Eq)]
struct KeyUsage {
    reads: usize,
    writes: usize,
}

fn split_call_arguments(arguments: &str) -> Vec<&str> {
    let bytes: &[u8] = arguments.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut depth: usize = 0;
    let mut start: usize = 0;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(&arguments[start..index]);
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    parts.push(&arguments[start..]);
    parts
}

fn metadata_owner_bindings_for_function(
    source: &str,
    function: Option<&SourceFunction>,
) -> BTreeSet<String> {
    let owner_type: String = metadata_owner_type_pattern(&metadata_owner_aliases(source));
    let typed_owner: Regex = Regex::new(
        &[
            r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&?\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s*)?(?:\[\s*)?(?:[A-Za-z_][A-Za-z0-9_]*::\s*)*",
            owner_type.as_str(),
            r"(?:\])?(?:[,\)])",
        ]
        .concat(),
    )
    .expect("typed metadata owner binding pattern");
    let function_source: &str = function.map_or(source, |scope: &SourceFunction| {
        source.get(scope.start..=scope.end).unwrap_or("")
    });
    typed_owner
        .captures_iter(function_source)
        .filter_map(|captures: regex::Captures<'_>| {
            captures
                .get(1)
                .map(|binding: regex::Match<'_>| binding.as_str().to_string())
        })
        .collect()
}

fn metadata_map_parameter_names(source: &str, function: &SourceFunction) -> BTreeSet<String> {
    let aliases: BTreeSet<String> = metadata_map_aliases(source);
    let map_type: String = metadata_map_type_pattern(&aliases);
    let parameters: Regex = Regex::new(&format!(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&?(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s*)?{map_type}"
    ))
    .expect("typed metadata parameter pattern");
    let function_source: &str = source.get(function.start..=function.end).unwrap_or("");
    parameters
        .captures_iter(function_source)
        .filter_map(|captures: regex::Captures<'_>| {
            captures
                .get(1)
                .map(|binding: regex::Match<'_>| binding.as_str().to_string())
        })
        .collect()
}

fn metadata_accessor_receiver_is_owned(
    source: &str,
    receiver: &str,
    position: usize,
    function: Option<&SourceFunction>,
    targeted_functions: &BTreeSet<String>,
) -> bool {
    let receiver: &str = receiver
        .trim()
        .strip_prefix("&mut")
        .or_else(|| receiver.strip_prefix('&'))
        .unwrap_or(receiver)
        .trim();
    if receiver.ends_with(".metadata")
        || receiver.contains(".metadata.")
        || receiver.contains(".metadata[")
    {
        let owner_bindings: BTreeSet<String> =
            metadata_owner_bindings_for_function(source, function);
        let root: &str = receiver.split(['.', '[']).next().unwrap_or(receiver);
        return owner_bindings.contains(root);
    }
    let Some(function): Option<&SourceFunction> = function else {
        return false;
    };
    targeted_functions.contains(&function.identity)
        && metadata_map_parameter_names(source, function).contains(receiver)
        && position > function.start
        && position < function.end
}

fn key_usage_in_sources<'source>(
    sources: impl IntoIterator<Item = &'source str>,
) -> BTreeMap<String, KeyUsage> {
    let source_texts: Vec<(String, String)> = sources
        .into_iter()
        .enumerate()
        .map(|(index, source): (usize, &str)| (format!("source-{index}"), code_only(source)))
        .collect();
    let targets: MetadataFunctionTargets = metadata_targeted_functions(
        source_texts
            .iter()
            .map(|(source_id, source): &(String, String)| (source_id.as_str(), source.as_str())),
    );
    let typed_access: Regex = Regex::new(
        r"((?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*(?:get|set)_(?:string|comma_list|integer|boolean|json))\(([^;{}]*)\)",
    )
    .expect("typed metadata access pattern");
    let key_alias: Regex =
        Regex::new(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]*_KEY)as([A-Z][A-Z0-9_]*)")
            .expect("metadata key alias pattern");
    let key_symbol: Regex = Regex::new(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]*)$")
        .expect("metadata key symbol pattern");
    let mut usage: BTreeMap<String, KeyUsage> = BTreeMap::new();
    for (source_id, lexical_source) in &source_texts {
        let compact: String = lexical_source
            .chars()
            .filter(|character: &char| !character.is_whitespace())
            .collect();
        let aliases: BTreeMap<String, String> = key_alias
            .captures_iter(&compact)
            .filter_map(|captures: regex::Captures<'_>| {
                let original: regex::Match<'_> = captures.get(1)?;
                let alias: regex::Match<'_> = captures.get(2)?;
                Some((alias.as_str().to_string(), original.as_str().to_string()))
            })
            .collect();
        let scopes: Vec<ScopeRange> = lexical_scopes(lexical_source);
        let functions: Vec<SourceFunction> = source_functions(lexical_source, &scopes);
        let imports: TypedAccessorImports =
            typed_accessor_imports(lexical_source, &scopes, &functions);
        let empty_targets: BTreeSet<String> = BTreeSet::new();
        let targeted_functions: &BTreeSet<String> =
            targets.by_source.get(source_id).unwrap_or(&empty_targets);
        for captures in typed_access.captures_iter(lexical_source) {
            let (Some(target), Some(arguments)): (
                Option<regex::Match<'_>>,
                Option<regex::Match<'_>>,
            ) = (captures.get(1), captures.get(2)) else {
                continue;
            };
            let Some(function): Option<&SourceFunction> =
                enclosing_function(&functions, target.start())
            else {
                continue;
            };
            if !is_typed_accessor_target(target.as_str(), target.start(), &imports) {
                continue;
            }
            let arguments: Vec<&str> = split_call_arguments(arguments.as_str());
            let (Some(receiver), Some(key_argument)): (Option<&&str>, Option<&&str>) =
                (arguments.first(), arguments.get(1))
            else {
                continue;
            };
            let key_argument: &str = key_argument.trim();
            let Some(symbol_capture): Option<regex::Match<'_>> = key_symbol
                .captures(key_argument)
                .and_then(|captures: regex::Captures<'_>| captures.get(1))
            else {
                continue;
            };
            if !metadata_accessor_receiver_is_owned(
                lexical_source,
                receiver,
                target.start(),
                Some(function),
                targeted_functions,
            ) {
                continue;
            }
            let resolved_symbol: &str = aliases
                .get(symbol_capture.as_str())
                .map_or(symbol_capture.as_str(), String::as_str);
            if !resolved_symbol.ends_with("_KEY") {
                continue;
            }
            let entry: &mut KeyUsage = usage.entry(resolved_symbol.to_string()).or_default();
            if target.as_str().ends_with("get_string")
                || target.as_str().ends_with("get_comma_list")
                || target.as_str().ends_with("get_integer")
                || target.as_str().ends_with("get_boolean")
                || target.as_str().ends_with("get_json")
            {
                entry.reads = entry.reads.saturating_add(1);
            } else {
                entry.writes = entry.writes.saturating_add(1);
            }
        }
    }
    usage
}

fn registered_key_usage(root: &Path) -> BTreeMap<String, KeyUsage> {
    let mut sources: Vec<String> = Vec::new();
    for path in rust_source_paths(&root.join("crates")) {
        if !path
            .components()
            .any(|component| component.as_os_str() == "src")
            || path.ends_with("crates/disrobe-core/src/chain/metadata_keys.rs")
        {
            continue;
        }
        let source: String =
            std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
                panic!("failed to read {}: {error}", path.display())
            });
        let production: String = without_test_cfg_items(&source);
        sources.push(production);
    }
    key_usage_in_sources(sources.iter().map(String::as_str))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MetadataFunctionTargets {
    by_source: BTreeMap<String, BTreeSet<String>>,
    returning_by_source: BTreeMap<String, BTreeSet<String>>,
    ambiguous: BTreeSet<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TypedAccessorImports {
    modules: BTreeMap<String, BTreeSet<TextRange>>,
    functions: BTreeMap<String, BTreeSet<TextRange>>,
}

fn import_visibility_range(
    scopes: &[ScopeRange],
    functions: &[SourceFunction],
    position: usize,
    source_len: usize,
) -> TextRange {
    enclosing_function(functions, position)
        .map(|function: &SourceFunction| TextRange {
            start: function.start,
            end: function.end,
        })
        .or_else(|| {
            scopes
                .iter()
                .filter(|scope: &&ScopeRange| scope.start < position && position < scope.end)
                .min_by_key(|scope: &&ScopeRange| scope.end.saturating_sub(scope.start))
                .map(|scope: &ScopeRange| TextRange {
                    start: scope.start,
                    end: scope.end,
                })
        })
        .unwrap_or_else(|| TextRange {
            start: 0,
            end: source_len.saturating_sub(1),
        })
}

fn typed_accessor_imports(
    source: &str,
    scopes: &[ScopeRange],
    functions: &[SourceFunction],
) -> TypedAccessorImports {
    let module_alias: Regex = Regex::new(
        r"\buse\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*metadata_keys\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
    )
    .expect("metadata accessor module alias pattern");
    let direct_import: Regex = Regex::new(
        r"\buse\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*metadata_keys\s*::\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;",
    )
    .expect("metadata accessor import pattern");
    let grouped_import: Regex = Regex::new(
        r"\buse\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*metadata_keys\s*::\s*\{([^}]*)\}\s*;",
    )
    .expect("metadata accessor group import pattern");
    let mut imports: TypedAccessorImports = TypedAccessorImports::default();
    insert_scoped_binding(
        &mut imports.modules,
        "metadata_keys",
        TextRange {
            start: 0,
            end: source.len().saturating_sub(1),
        },
    );
    for captures in module_alias.captures_iter(source) {
        let (Some(declaration), Some(alias)): (Option<regex::Match<'_>>, Option<regex::Match<'_>>) =
            (captures.get(0), captures.get(1))
        else {
            continue;
        };
        let range: TextRange =
            import_visibility_range(scopes, functions, declaration.start(), source.len());
        insert_scoped_binding(&mut imports.modules, alias.as_str(), range);
    }
    for captures in direct_import.captures_iter(source) {
        let (Some(declaration), Some(accessor)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        if !TYPED_METADATA_ACCESSORS.contains(&accessor.as_str()) {
            continue;
        }
        let imported_name: &str = captures
            .get(2)
            .map_or(accessor.as_str(), |alias: regex::Match<'_>| alias.as_str());
        let range: TextRange =
            import_visibility_range(scopes, functions, declaration.start(), source.len());
        insert_scoped_binding(&mut imports.functions, imported_name, range);
    }
    for captures in grouped_import.captures_iter(source) {
        let (Some(declaration), Some(entries)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let range: TextRange =
            import_visibility_range(scopes, functions, declaration.start(), source.len());
        for entry in entries.as_str().split(',').map(str::trim) {
            let (name, alias): (&str, Option<&str>) = entry
                .split_once(" as ")
                .map_or((entry, None), |(name, alias): (&str, &str)| {
                    (name.trim(), Some(alias.trim()))
                });
            if name == "self" {
                insert_scoped_binding(
                    &mut imports.modules,
                    alias.unwrap_or("metadata_keys"),
                    range,
                );
            } else if TYPED_METADATA_ACCESSORS.contains(&name) {
                insert_scoped_binding(&mut imports.functions, alias.unwrap_or(name), range);
            }
        }
    }
    imports
}

fn is_typed_accessor_target(target: &str, position: usize, imports: &TypedAccessorImports) -> bool {
    if imports
        .functions
        .get(target)
        .is_some_and(|ranges: &BTreeSet<TextRange>| position_is_in_ranges(position, ranges))
    {
        return true;
    }
    let Some((qualifier, function)): Option<(&str, &str)> = target.rsplit_once("::") else {
        return false;
    };
    TYPED_METADATA_ACCESSORS.contains(&function)
        && (qualifier.ends_with("metadata_keys")
            || imports
                .modules
                .get(qualifier)
                .is_some_and(|ranges: &BTreeSet<TextRange>| {
                    position_is_in_ranges(position, ranges)
                }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeRange {
    name: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionDefinition {
    source_id: String,
    identity: String,
    parameter: Option<String>,
    returns_map: bool,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFunction {
    identity: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataFlowContext {
    start: usize,
    end: usize,
    owner_bindings: BTreeSet<String>,
    metadata_aliases: BTreeSet<String>,
    local_metadata_bindings: BTreeSet<String>,
}

fn lexical_scopes(source: &str) -> Vec<ScopeRange> {
    let scope_start: Regex =
        Regex::new(r"\b(?:mod|impl)\s*(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)[^;\{]*\{")
            .expect("lexical scope pattern");
    let bytes: &[u8] = source.as_bytes();
    let mut scopes: Vec<ScopeRange> = scope_start
        .captures_iter(source)
        .filter_map(|captures: regex::Captures<'_>| {
            let whole: regex::Match<'_> = captures.get(0)?;
            let name: regex::Match<'_> = captures.get(1)?;
            let opening: usize = whole.end().checked_sub(1)?;
            let closing: usize = matching_delimiter(bytes, opening, b'{', b'}')?;
            Some(ScopeRange {
                name: name.as_str().to_string(),
                start: opening,
                end: closing,
            })
        })
        .collect();
    scopes.sort_unstable_by_key(|scope: &ScopeRange| (scope.start, std::cmp::Reverse(scope.end)));
    scopes
}

fn scope_path_at(scopes: &[ScopeRange], position: usize) -> Vec<&str> {
    scopes
        .iter()
        .filter(|scope: &&ScopeRange| scope.start < position && position < scope.end)
        .map(|scope: &ScopeRange| scope.name.as_str())
        .collect()
}

fn qualified_identity(scopes: &[ScopeRange], position: usize, name: &str) -> String {
    let path: Vec<&str> = scope_path_at(scopes, position);
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", path.join("::"))
    }
}

fn source_functions(source: &str, scopes: &[ScopeRange]) -> Vec<SourceFunction> {
    let function_start: Regex =
        Regex::new(r"\bfn\s*([A-Za-z_][A-Za-z0-9_]*)[^\(\{;]*\(").expect("function scope pattern");
    let bytes: &[u8] = source.as_bytes();
    let mut functions: Vec<SourceFunction> = function_start
        .captures_iter(source)
        .filter_map(|captures: regex::Captures<'_>| {
            let whole: regex::Match<'_> = captures.get(0)?;
            let name: regex::Match<'_> = captures.get(1)?;
            let parameters_open: usize = whole.end().checked_sub(1)?;
            let parameters_close: usize = matching_delimiter(bytes, parameters_open, b'(', b')')?;
            let body_offset: usize = source[parameters_close.saturating_add(1)..].find('{')?;
            let body_open: usize = parameters_close
                .saturating_add(1)
                .saturating_add(body_offset);
            let body_close: usize = matching_delimiter(bytes, body_open, b'{', b'}')?;
            Some(SourceFunction {
                identity: qualified_identity(scopes, name.start(), name.as_str()),
                start: whole.start(),
                end: body_close,
            })
        })
        .collect();
    functions.sort_unstable_by_key(|function: &SourceFunction| {
        (function.start, std::cmp::Reverse(function.end))
    });
    functions
}

fn enclosing_function(functions: &[SourceFunction], position: usize) -> Option<&SourceFunction> {
    functions
        .iter()
        .filter(|function: &&SourceFunction| function.start < position && position < function.end)
        .min_by_key(|function: &&SourceFunction| function.end.saturating_sub(function.start))
}

fn default_owner_bindings() -> BTreeSet<String> {
    BTreeSet::from([
        "node".to_string(),
        "nodes".to_string(),
        "n".to_string(),
        "outcome".to_string(),
        "outcomes".to_string(),
    ])
}

fn source_matches_qualifier(source_id: &str, qualifier: &str) -> bool {
    let normalized_source: String = source_id.replace('\\', "/");
    let normalized_qualifier: String = qualifier.replace("::", "/");
    normalized_source.ends_with(&format!("/{normalized_qualifier}.rs"))
        || normalized_source.ends_with(&format!("/{normalized_qualifier}/mod.rs"))
        || normalized_source == format!("{normalized_qualifier}.rs")
        || normalized_source == format!("{normalized_qualifier}/mod.rs")
}

fn contains_identifier_argument(source: &str, identifier: &str) -> bool {
    source
        .match_indices(identifier)
        .any(|(index, matched): (usize, &str)| {
            let preceding: &[u8] = &source.as_bytes()[..index];
            let preceding_boundary: bool = index == 0
                || preceding
                    .last()
                    .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_')
                || preceding.ends_with(b"&mut");
            let following_index: usize = index.saturating_add(matched.len());
            let following_boundary: bool = source
                .as_bytes()
                .get(following_index)
                .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_');
            preceding_boundary && following_boundary
        })
}

fn contains_metadata_field_argument(source: &str, binding: &str) -> bool {
    source
        .match_indices(binding)
        .any(|(index, matched): (usize, &str)| {
            let preceding: &[u8] = &source.as_bytes()[..index];
            let preceding_boundary: bool = index == 0
                || preceding
                    .last()
                    .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_')
                || preceding.ends_with(b"&mut");
            if !preceding_boundary {
                return false;
            }
            let suffix: &str = &source[index.saturating_add(matched.len())..];
            if suffix.starts_with(".metadata")
                && suffix.as_bytes().get(".metadata".len()) != Some(&b'(')
            {
                return true;
            }
            let Some(indexed_suffix): Option<&str> = suffix.strip_prefix('[') else {
                return false;
            };
            indexed_suffix.find(']').is_some_and(|closing: usize| {
                indexed_suffix[closing.saturating_add(1)..].starts_with(".metadata")
            })
        })
}

fn contains_owned_metadata_field_argument(source: &str, owner_bindings: &BTreeSet<String>) -> bool {
    owner_bindings
        .iter()
        .any(|binding: &String| contains_metadata_field_argument(source, binding))
        || [".node.metadata", ".outcome.metadata"]
            .iter()
            .any(|field: &&str| source.contains(field))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TextRange {
    start: usize,
    end: usize,
}

fn expression_is_function_result(
    source: &str,
    expression_start: usize,
    expression_end: usize,
    function_start: usize,
    function_end: usize,
) -> bool {
    let prefix: &str = source.get(function_start..expression_start).unwrap_or("");
    let trimmed_prefix: &str = prefix.trim_end();
    let explicit_return: bool =
        trimmed_prefix
            .strip_suffix("return")
            .is_some_and(|before: &str| {
                before
                    .as_bytes()
                    .last()
                    .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_')
            });
    let suffix: &str = source.get(expression_end..=function_end).unwrap_or("");
    explicit_return || suffix.trim_start().starts_with('}')
}

fn text_range_at(functions: &[SourceFunction], position: usize, source_len: usize) -> TextRange {
    enclosing_function(functions, position).map_or_else(
        || TextRange {
            start: 0,
            end: source_len.saturating_sub(1),
        },
        |function: &SourceFunction| TextRange {
            start: function.start,
            end: function.end,
        },
    )
}

fn insert_scoped_binding(
    bindings: &mut BTreeMap<String, BTreeSet<TextRange>>,
    name: &str,
    range: TextRange,
) -> bool {
    bindings.entry(name.to_string()).or_default().insert(range)
}

fn position_is_in_ranges(position: usize, ranges: &BTreeSet<TextRange>) -> bool {
    ranges
        .iter()
        .any(|range: &TextRange| range.start <= position && position <= range.end)
}

fn scoped_metadata_receiver_is_owned(
    receiver: &str,
    position: usize,
    owner_bindings: &BTreeMap<String, BTreeSet<TextRange>>,
) -> bool {
    if receiver.contains(".node.metadata") || receiver.contains(".outcome.metadata") {
        return true;
    }
    let root: &str = receiver.split(['.', '[']).next().unwrap_or(receiver);
    owner_bindings
        .get(root)
        .is_some_and(|ranges: &BTreeSet<TextRange>| position_is_in_ranges(position, ranges))
}

fn scoped_source<'source>(source: &'source str, range: &TextRange) -> &'source str {
    source.get(range.start..=range.end).unwrap_or("")
}

fn metadata_map_aliases(source: &str) -> BTreeSet<String> {
    let alias: Regex = Regex::new(
        r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>]*>)?\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*BTreeMap\s*<\s*String\s*,\s*String\s*>",
    )
    .expect("metadata map type alias pattern");
    alias
        .captures_iter(source)
        .filter_map(|captures: regex::Captures<'_>| {
            captures
                .get(1)
                .map(|name: regex::Match<'_>| name.as_str().to_string())
        })
        .collect()
}

fn metadata_map_type_pattern(aliases: &BTreeSet<String>) -> String {
    let mut alternatives: Vec<String> = vec![
        r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*BTreeMap\s*<\s*String\s*,\s*String\s*>".to_string(),
    ];
    alternatives.extend(aliases.iter().map(|alias: &String| {
        format!(
            r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*{}(?:\s*<[^>]+>)?",
            regex::escape(alias)
        )
    }));
    format!("(?:{})", alternatives.join("|"))
}

fn metadata_owner_aliases(source: &str) -> BTreeSet<String> {
    let alias: Regex = Regex::new(
        r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>]*>)?\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*(?:Node|PassRunOutcome)\b",
    )
    .expect("metadata owner type alias pattern");
    alias
        .captures_iter(source)
        .filter_map(|captures: regex::Captures<'_>| {
            captures
                .get(1)
                .map(|name: regex::Match<'_>| name.as_str().to_string())
        })
        .collect()
}

fn metadata_owner_type_pattern(aliases: &BTreeSet<String>) -> String {
    let mut alternatives: Vec<String> = vec!["Node".to_string(), "PassRunOutcome".to_string()];
    alternatives.extend(aliases.iter().map(|alias: &String| regex::escape(alias)));
    format!("(?:{})", alternatives.join("|"))
}

fn metadata_targeted_functions<'source>(
    sources: impl IntoIterator<Item = (&'source str, &'source str)>,
) -> MetadataFunctionTargets {
    let invocation: Regex = Regex::new(
        r"(?:^|[^A-Za-z0-9_])((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*[A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}\)]*)\)",
    )
    .expect("function invocation pattern");
    let chain_node_iteration: Regex = Regex::new(
        r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+&(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\.nodes",
    )
    .expect("chain node iteration pattern");
    let chain_plan_binding: Regex = Regex::new(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&(?:mut\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*ChainPlan(?:\s*[,\)])",
    )
    .expect("chain plan binding pattern");
    let source_texts: Vec<(String, String)> = sources
        .into_iter()
        .map(|(source_id, source): (&str, &str)| (source_id.to_string(), code_only(source)))
        .collect();
    let map_aliases: BTreeSet<String> = source_texts
        .iter()
        .flat_map(|(_source_id, source): &(String, String)| metadata_map_aliases(source))
        .collect();
    let map_type: String = metadata_map_type_pattern(&map_aliases);
    let definition: Regex = Regex::new(&format!(
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)[^\(]*\([^\)]*?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&?\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s*)?{map_type}"
    ))
    .expect("typed metadata function pattern");
    let return_definition: Regex = Regex::new(&format!(
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)[^\(]*\([^\)]*\)\s*->\s*{map_type}"
    ))
    .expect("metadata return function pattern");
    let metadata_alias: Regex = Regex::new(&format!(
        r"let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s*)?{map_type}\s*=\s*&\s*(?:mut\s*)?((?:[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^]]+\])?\s*\.\s*)+metadata)"
    ))
    .expect("typed metadata alias pattern");
    let mut definitions: BTreeMap<String, Vec<FunctionDefinition>> = BTreeMap::new();
    let mut source_scopes: BTreeMap<String, Vec<ScopeRange>> = BTreeMap::new();
    let mut accessor_imports_by_source: BTreeMap<String, TypedAccessorImports> = BTreeMap::new();
    let mut flow_by_source: BTreeMap<String, Vec<MetadataFlowContext>> = BTreeMap::new();
    let mut metadata_initializers: BTreeMap<String, Regex> = BTreeMap::new();
    for (source_id, source) in &source_texts {
        let owner_type: String = metadata_owner_type_pattern(&metadata_owner_aliases(source));
        let typed_owner: Regex = Regex::new(
            &[
                r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&?\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s*)?(?:\[\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*",
                owner_type.as_str(),
                r"(?:\s*\])?",
            ]
            .concat(),
        )
        .expect("typed metadata owner binding pattern");
        let metadata_field_binding: Regex = Regex::new(
            &[
                r"(?:[A-Za-z_][A-Za-z0-9_]*::)?",
                owner_type.as_str(),
                r"\s*\{[^}]*metadata\s*(?::\s*([A-Za-z_][A-Za-z0-9_]*))?(?:\s*[,}])",
            ]
            .concat(),
        )
        .expect("metadata output binding pattern");
        let metadata_initializer: Regex = Regex::new(
            &[
                r"(?:[A-Za-z_][A-Za-z0-9_]*::)?",
                owner_type.as_str(),
                r"\s*\{[^{}]*metadata\s*:\s*$",
            ]
            .concat(),
        )
        .expect("metadata initializer pattern");
        metadata_initializers.insert(source_id.clone(), metadata_initializer);
        let scopes: Vec<ScopeRange> = lexical_scopes(source);
        let functions: Vec<SourceFunction> = source_functions(source, &scopes);
        for captures in definition.captures_iter(source) {
            let (Some(function), Some(parameter), Some(signature)): (
                Option<regex::Match<'_>>,
                Option<regex::Match<'_>>,
                Option<regex::Match<'_>>,
            ) = (captures.get(1), captures.get(2), captures.get(0)) else {
                continue;
            };
            let Some(relative_opening): Option<usize> = source[signature.end()..].find('{') else {
                continue;
            };
            let opening: usize = signature.end().saturating_add(relative_opening);
            let Some(end): Option<usize> =
                matching_delimiter(source.as_bytes(), opening, b'{', b'}')
            else {
                continue;
            };
            definitions
                .entry(function.as_str().to_string())
                .or_default()
                .push(FunctionDefinition {
                    source_id: source_id.clone(),
                    identity: qualified_identity(&scopes, function.start(), function.as_str()),
                    parameter: Some(parameter.as_str().to_string()),
                    returns_map: false,
                    start: function.start(),
                    end,
                });
        }
        for captures in return_definition.captures_iter(source) {
            let (Some(function), Some(signature)): (
                Option<regex::Match<'_>>,
                Option<regex::Match<'_>>,
            ) = (captures.get(1), captures.get(0)) else {
                continue;
            };
            let Some(relative_opening): Option<usize> = source[signature.end()..].find('{') else {
                continue;
            };
            let opening: usize = signature.end().saturating_add(relative_opening);
            let Some(end): Option<usize> =
                matching_delimiter(source.as_bytes(), opening, b'{', b'}')
            else {
                continue;
            };
            let identity: String = qualified_identity(&scopes, function.start(), function.as_str());
            let entries: &mut Vec<FunctionDefinition> = definitions
                .entry(function.as_str().to_string())
                .or_default();
            if let Some(existing) =
                entries
                    .iter_mut()
                    .find(|candidate: &&mut FunctionDefinition| {
                        candidate.source_id == *source_id && candidate.start == function.start()
                    })
            {
                existing.returns_map = true;
            } else {
                entries.push(FunctionDefinition {
                    source_id: source_id.clone(),
                    identity,
                    parameter: None,
                    returns_map: true,
                    start: function.start(),
                    end,
                });
            }
        }
        let flow_contexts: Vec<MetadataFlowContext> = functions
            .iter()
            .map(|function: &SourceFunction| {
                let function_source: &str = &source[function.start..=function.end];
                let mut owner_bindings: BTreeSet<String> = typed_owner
                    .captures_iter(function_source)
                    .filter_map(|captures: regex::Captures<'_>| {
                        captures
                            .get(1)
                            .map(|binding: regex::Match<'_>| binding.as_str().to_string())
                    })
                    .collect();
                let chain_plan_bindings: BTreeSet<String> = chain_plan_binding
                    .captures_iter(function_source)
                    .filter_map(|captures: regex::Captures<'_>| {
                        captures
                            .get(1)
                            .map(|plan: regex::Match<'_>| plan.as_str().to_string())
                    })
                    .collect();
                owner_bindings.extend(
                    chain_node_iteration
                        .captures_iter(function_source)
                        .filter_map(|captures: regex::Captures<'_>| {
                            let binding: &str = captures.get(1)?.as_str();
                            let owner: &str = captures.get(2)?.as_str();
                            chain_plan_bindings
                                .contains(owner)
                                .then(|| binding.to_string())
                        }),
                );
                let impl_scope: &str = function
                    .identity
                    .strip_suffix(
                        function
                            .identity
                            .rsplit("::")
                            .next()
                            .unwrap_or(function.identity.as_str()),
                    )
                    .unwrap_or("")
                    .trim_end_matches("::");
                if matches!(
                    impl_scope.rsplit("::").next(),
                    Some("Node" | "PassRunOutcome")
                ) {
                    owner_bindings.insert("self".to_string());
                }
                let local_metadata_bindings: BTreeSet<String> = metadata_field_binding
                    .captures_iter(function_source)
                    .map(|captures: regex::Captures<'_>| {
                        captures
                            .get(1)
                            .map_or("metadata", |binding: regex::Match<'_>| binding.as_str())
                    })
                    .map(str::to_string)
                    .collect();
                let metadata_aliases: BTreeSet<String> = metadata_alias
                    .captures_iter(function_source)
                    .filter_map(|captures: regex::Captures<'_>| {
                        let alias: regex::Match<'_> = captures.get(1)?;
                        let receiver: regex::Match<'_> = captures.get(2)?;
                        let root: &str = receiver.as_str().split(['.', '[']).next()?.trim();
                        owner_bindings
                            .contains(root)
                            .then(|| alias.as_str().to_string())
                    })
                    .collect();
                MetadataFlowContext {
                    start: function.start,
                    end: function.end,
                    owner_bindings,
                    metadata_aliases,
                    local_metadata_bindings,
                }
            })
            .collect();
        accessor_imports_by_source.insert(
            source_id.clone(),
            typed_accessor_imports(source, &scopes, &functions),
        );
        flow_by_source.insert(source_id.clone(), flow_contexts);
        source_scopes.insert(source_id.clone(), scopes);
    }
    let mut targets: MetadataFunctionTargets = MetadataFunctionTargets::default();
    let mut changed: bool = true;
    while changed {
        changed = false;
        for (caller_id, source) in &source_texts {
            let Some(accessor_imports): Option<&TypedAccessorImports> =
                accessor_imports_by_source.get(caller_id)
            else {
                continue;
            };
            for captures in invocation.captures_iter(source) {
                let Some(call): Option<regex::Match<'_>> = captures.get(0) else {
                    continue;
                };
                let Some(target): Option<regex::Match<'_>> = captures.get(1) else {
                    continue;
                };
                let Some(arguments): Option<regex::Match<'_>> = captures.get(2) else {
                    continue;
                };
                if definitions
                    .values()
                    .flatten()
                    .any(|candidate: &FunctionDefinition| {
                        candidate.source_id == *caller_id && candidate.start == target.start()
                    })
                {
                    continue;
                }
                let caller: Option<&FunctionDefinition> = definitions
                    .values()
                    .flatten()
                    .filter(|candidate: &&FunctionDefinition| {
                        candidate.source_id == *caller_id
                            && candidate.start < target.start()
                            && target.start() < candidate.end
                    })
                    .min_by_key(|candidate: &&FunctionDefinition| candidate.end - candidate.start);
                let flow: Option<&MetadataFlowContext> = flow_by_source.get(caller_id).and_then(
                    |contexts: &Vec<MetadataFlowContext>| {
                        contexts
                            .iter()
                            .filter(|context: &&MetadataFlowContext| {
                                context.start < target.start() && target.start() < context.end
                            })
                            .min_by_key(|context: &&MetadataFlowContext| {
                                context.end.saturating_sub(context.start)
                            })
                    },
                );
                let fallback_owners: BTreeSet<String> = default_owner_bindings();
                let owner_bindings: &BTreeSet<String> = flow
                    .map_or(&fallback_owners, |context: &MetadataFlowContext| {
                        &context.owner_bindings
                    });
                let arguments_compact: String = arguments
                    .as_str()
                    .chars()
                    .filter(|character: &char| !character.is_whitespace())
                    .collect();
                let direct_metadata: bool =
                    contains_owned_metadata_field_argument(&arguments_compact, owner_bindings)
                        || flow.is_some_and(|context: &MetadataFlowContext| {
                            context
                                .local_metadata_bindings
                                .iter()
                                .any(|binding: &String| {
                                    contains_identifier_argument(&arguments_compact, binding)
                                })
                        });
                let aliased_metadata: bool = flow.is_some_and(|context: &MetadataFlowContext| {
                    context.metadata_aliases.iter().any(|alias: &String| {
                        contains_identifier_argument(&arguments_compact, alias)
                    })
                });
                let propagated_metadata: bool =
                    caller.is_some_and(|definition: &FunctionDefinition| {
                        targets.by_source.get(caller_id).is_some_and(
                            |identities: &BTreeSet<String>| {
                                identities.contains(&definition.identity)
                            },
                        ) && definition
                            .parameter
                            .as_ref()
                            .is_some_and(|parameter: &String| {
                                contains_identifier_argument(&arguments_compact, parameter)
                            })
                    });
                let returned_metadata: bool =
                    caller.is_some_and(|definition: &FunctionDefinition| {
                        definition.returns_map
                            && targets.returning_by_source.get(caller_id).is_some_and(
                                |identities: &BTreeSet<String>| {
                                    identities.contains(&definition.identity)
                                },
                            )
                            && expression_is_function_result(
                                source,
                                target.start(),
                                call.end(),
                                definition.start,
                                definition.end,
                            )
                    });
                let initializes_metadata: bool =
                    metadata_initializers
                        .get(caller_id)
                        .is_some_and(|initializer: &Regex| {
                            initializer.is_match(&source[..target.start()])
                        });
                if !(direct_metadata
                    || aliased_metadata
                    || propagated_metadata
                    || returned_metadata
                    || initializes_metadata)
                {
                    continue;
                }
                let target_name_owned: String = target
                    .as_str()
                    .chars()
                    .filter(|character: &char| !character.is_whitespace())
                    .collect();
                let target_name: &str = target_name_owned.as_str();
                let function: &str = target_name.rsplit("::").next().unwrap_or(target_name);
                if is_typed_accessor_target(target_name, target.start(), accessor_imports) {
                    continue;
                }
                if initializes_metadata
                    && matches!(function, "new" | "default")
                    && target_name.rsplit_once("::").is_some_and(
                        |(qualifier, _function): (&str, &str)| {
                            qualifier.ends_with("BTreeMap") || qualifier.ends_with("Default")
                        },
                    )
                {
                    continue;
                }
                let candidates: &[FunctionDefinition] =
                    definitions.get(function).map_or(&[], Vec::as_slice);
                let caller_scopes: &[ScopeRange] =
                    source_scopes.get(caller_id).map_or(&[], Vec::as_slice);
                let caller_path: Vec<&str> = scope_path_at(caller_scopes, target.start());
                let mut matches: Vec<&FunctionDefinition> = if let Some((qualifier, _function)) =
                    target_name.rsplit_once("::")
                {
                    let resolved_qualifier: String = if qualifier == "Self" {
                        caller_path.last().copied().unwrap_or(qualifier).to_string()
                    } else if qualifier == "super" {
                        caller_path
                            .get(caller_path.len().saturating_sub(2))
                            .copied()
                            .unwrap_or(qualifier)
                            .to_string()
                    } else {
                        qualifier.to_string()
                    };
                    candidates
                        .iter()
                        .filter(|candidate: &&FunctionDefinition| {
                            !(initializes_metadata || returned_metadata) || candidate.returns_map
                        })
                        .filter(|candidate: &&FunctionDefinition| {
                            candidate.source_id == *caller_id
                                && candidate.identity == format!("{resolved_qualifier}::{function}")
                                || source_matches_qualifier(
                                    &candidate.source_id,
                                    &resolved_qualifier,
                                )
                        })
                        .collect()
                } else {
                    let mut local: Vec<&FunctionDefinition> = candidates
                        .iter()
                        .filter(|candidate: &&FunctionDefinition| {
                            !(initializes_metadata || returned_metadata) || candidate.returns_map
                        })
                        .filter(|candidate: &&FunctionDefinition| candidate.source_id == *caller_id)
                        .filter(|candidate: &&FunctionDefinition| {
                            let candidate_scope: &str = candidate
                                .identity
                                .strip_suffix(&format!("::{function}"))
                                .unwrap_or("");
                            candidate_scope.is_empty()
                                || caller_path.join("::") == candidate_scope
                                || caller_path
                                    .join("::")
                                    .starts_with(&format!("{candidate_scope}::"))
                        })
                        .collect();
                    local.sort_unstable_by_key(|candidate: &&FunctionDefinition| {
                        std::cmp::Reverse(candidate.identity.matches("::").count())
                    });
                    if local.len() > 1 {
                        let depth: usize = local[0].identity.matches("::").count();
                        local.retain(|candidate: &&FunctionDefinition| {
                            candidate.identity.matches("::").count() == depth
                        });
                    }
                    if local.is_empty() && candidates.len() == 1 {
                        candidates.iter().collect()
                    } else {
                        local
                    }
                };
                matches.sort_unstable_by(
                    |left: &&FunctionDefinition, right: &&FunctionDefinition| {
                        (&left.source_id, &left.identity).cmp(&(&right.source_id, &right.identity))
                    },
                );
                matches.dedup_by(
                    |left: &mut &FunctionDefinition, right: &mut &FunctionDefinition| {
                        left.source_id == right.source_id && left.identity == right.identity
                    },
                );
                if let [definition] = matches.as_slice() {
                    let inserted: bool = targets
                        .by_source
                        .entry(definition.source_id.clone())
                        .or_default()
                        .insert(definition.identity.clone());
                    let returning_inserted: bool = (initializes_metadata || returned_metadata)
                        && targets
                            .returning_by_source
                            .entry(definition.source_id.clone())
                            .or_default()
                            .insert(definition.identity.clone());
                    changed |= inserted || returning_inserted;
                } else {
                    targets.ambiguous.insert(target_name.to_string());
                }
            }
        }
    }
    targets
}

fn returning_map_uses_raw_construction(
    source: &str,
    functions: &[SourceFunction],
    returning_functions: &BTreeSet<String>,
) -> bool {
    let construction: Regex = Regex::new(
        r"(?:(?:[A-Za-z_][A-Za-z0-9_]*::)*BTreeMap(?:::[^>]+>)?::(?:from|from_iter)|collect::<(?:[A-Za-z_][A-Za-z0-9_]*::)*BTreeMap<[^>]+>>)\(",
    )
    .expect("returned metadata construction pattern");
    construction
        .find_iter(source)
        .any(|expression: regex::Match<'_>| {
            let Some(opening): Option<usize> = expression.end().checked_sub(1) else {
                return false;
            };
            let Some(closing): Option<usize> =
                matching_delimiter(source.as_bytes(), opening, b'(', b')')
            else {
                return false;
            };
            let Some(function): Option<&SourceFunction> =
                enclosing_function(functions, expression.start())
            else {
                return false;
            };
            returning_functions.contains(&function.identity)
                && expression_is_function_result(
                    source,
                    expression.start(),
                    closing.saturating_add(1),
                    function.start,
                    function.end,
                )
        })
}

fn direct_metadata_key_accesses(
    source: &str,
    metadata_functions: &BTreeSet<String>,
    returning_functions: &BTreeSet<String>,
) -> Vec<&'static str> {
    let aliases: BTreeSet<String> = metadata_map_aliases(source);
    direct_metadata_key_accesses_with_aliases(
        source,
        metadata_functions,
        returning_functions,
        &aliases,
    )
}

fn direct_metadata_key_accesses_with_aliases(
    source: &str,
    metadata_functions: &BTreeSet<String>,
    returning_functions: &BTreeSet<String>,
    known_map_aliases: &BTreeSet<String>,
) -> Vec<&'static str> {
    let lexical_source: String = code_only(source);
    let compact_source: String = lexical_source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect();
    let mut map_aliases: BTreeSet<String> = metadata_map_aliases(&lexical_source);
    map_aliases.extend(known_map_aliases.iter().cloned());
    let map_type: String = metadata_map_type_pattern(&map_aliases);
    let typed_parameter: Regex = Regex::new(&format!(
        r"fn([A-Za-z_][A-Za-z0-9_]*)[^\(]*\([^\)]*?([A-Za-z_][A-Za-z0-9_]*):&?(?:'[A-Za-z_][A-Za-z0-9_]*)?(?:mut)?{map_type}"
    ))
    .expect("typed metadata parameter pattern");
    let alias_binding: Regex = Regex::new(
        r"let(?:mut)?([A-Za-z_][A-Za-z0-9_]*)(?::[^=;]+)?=(?:&(?:mut)?)?((?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]+\])?\.)*[A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("metadata alias pattern");
    let owner_type: String = metadata_owner_type_pattern(&metadata_owner_aliases(&lexical_source));
    let metadata_field_binding: Regex = Regex::new(
        &[
            r"(?:[A-Za-z_][A-Za-z0-9_]*::)?",
            owner_type.as_str(),
            r"\{[^}]*metadata(?::([A-Za-z_][A-Za-z0-9_]*))?(?:[,}])",
        ]
        .concat(),
    )
    .expect("metadata field binding pattern");
    let typed_metadata_local: Regex = Regex::new(&format!(r"let(?:mut)?metadata:{map_type}"))
        .expect("typed metadata local pattern");
    let typed_map_local: Regex = Regex::new(&format!(
        r"let(?:mut)?([A-Za-z_][A-Za-z0-9_]*)(?::{map_type})?=(?:[A-Za-z_][A-Za-z0-9_]*::)*BTreeMap(?:::[^>]+>)?::(?:new|default|from|from_iter)\("
    ))
    .expect("typed map local pattern");
    let metadata_field_receiver: Regex =
        Regex::new(r"((?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.)+metadata)(?:\.|\[|=|,|\))")
            .expect("metadata field receiver pattern");
    let scopes: Vec<ScopeRange> = lexical_scopes(&compact_source);
    let functions: Vec<SourceFunction> = source_functions(&compact_source, &scopes);
    let compact: String = compact_source.clone();
    let typed_owner: Regex = Regex::new(
        &[
            r"([A-Za-z_][A-Za-z0-9_]*):&?(?:'[A-Za-z_][A-Za-z0-9_]*)?(?:mut)?(?:\[)?(?:[A-Za-z_][A-Za-z0-9_]*::)*",
            owner_type.as_str(),
            r"(?:\])?(?:[,\)])",
        ]
        .concat(),
    )
    .expect("metadata owner binding pattern");
    let mut owner_bindings: BTreeMap<String, BTreeSet<TextRange>> = BTreeMap::new();
    if functions.is_empty() {
        let range: TextRange = text_range_at(&functions, 0, compact.len());
        for binding in default_owner_bindings() {
            insert_scoped_binding(&mut owner_bindings, &binding, range);
        }
    }
    for captures in typed_owner.captures_iter(&compact) {
        let (Some(binding), Some(declaration)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (captures.get(1), captures.get(0)) else {
            continue;
        };
        let range: TextRange = text_range_at(&functions, declaration.start(), compact.len());
        insert_scoped_binding(&mut owner_bindings, binding.as_str(), range);
    }
    for function in &functions {
        let impl_scope: &str = function
            .identity
            .rsplit_once("::")
            .map_or("", |(scope, _name): (&str, &str)| scope);
        if matches!(
            impl_scope.rsplit("::").next(),
            Some("Node" | "PassRunOutcome")
        ) {
            insert_scoped_binding(
                &mut owner_bindings,
                "self",
                TextRange {
                    start: function.start,
                    end: function.end,
                },
            );
        }
    }
    let mut receivers: BTreeMap<String, BTreeSet<TextRange>> = BTreeMap::new();
    for captures in typed_map_local.captures_iter(&compact) {
        let (Some(binding), Some(declaration)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (captures.get(1), captures.get(0)) else {
            continue;
        };
        let function: Option<&SourceFunction> = enclosing_function(&functions, declaration.start());
        if function.is_some_and(|function: &SourceFunction| {
            returning_functions.contains(&function.identity)
        }) {
            let range: TextRange = text_range_at(&functions, declaration.start(), compact.len());
            insert_scoped_binding(&mut receivers, binding.as_str(), range);
        }
    }
    for declaration in typed_metadata_local.find_iter(&compact) {
        let range: TextRange = text_range_at(&functions, declaration.start(), compact.len());
        if scoped_source(&compact, &range).contains("metadata,") {
            insert_scoped_binding(&mut receivers, "metadata", range);
        }
    }
    for captures in metadata_field_binding.captures_iter(&compact) {
        let Some(initializer): Option<regex::Match<'_>> = captures.get(0) else {
            continue;
        };
        let binding: &str = captures
            .get(1)
            .map_or("metadata", |binding: regex::Match<'_>| binding.as_str());
        let range: TextRange = text_range_at(&functions, initializer.start(), compact.len());
        insert_scoped_binding(&mut receivers, binding, range);
    }
    for captures in metadata_field_receiver.captures_iter(&compact) {
        let Some(receiver): Option<regex::Match<'_>> = captures.get(1) else {
            continue;
        };
        if !scoped_metadata_receiver_is_owned(receiver.as_str(), receiver.start(), &owner_bindings)
        {
            continue;
        }
        let range: TextRange = text_range_at(&functions, receiver.start(), compact.len());
        insert_scoped_binding(&mut receivers, receiver.as_str(), range);
    }
    for captures in typed_parameter.captures_iter(&compact_source) {
        let (Some(function), Some(parameter)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let identity: String = qualified_identity(&scopes, function.start(), function.as_str());
        if metadata_functions.contains(&identity) {
            let range: TextRange = text_range_at(&functions, function.start(), compact.len());
            insert_scoped_binding(&mut receivers, parameter.as_str(), range);
        }
    }
    loop {
        let mut changed: bool = false;
        for captures in alias_binding.captures_iter(&compact) {
            let (Some(alias), Some(target)): (Option<regex::Match<'_>>, Option<regex::Match<'_>>) =
                (captures.get(1), captures.get(2))
            else {
                continue;
            };
            let target_name: &str = target
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or(target.as_str());
            let field_metadata: bool = target.as_str().ends_with(".metadata")
                && compact.as_bytes().get(target.end()) != Some(&b'(')
                && scoped_metadata_receiver_is_owned(
                    target.as_str(),
                    target.start(),
                    &owner_bindings,
                );
            let target_is_scoped: bool =
                receivers
                    .get(target_name)
                    .is_some_and(|ranges: &BTreeSet<TextRange>| {
                        position_is_in_ranges(alias.start(), ranges)
                    });
            if field_metadata || target_is_scoped {
                let range: TextRange = text_range_at(&functions, alias.start(), compact.len());
                changed |= insert_scoped_binding(&mut receivers, alias.as_str(), range);
            }
        }
        if !changed {
            break;
        }
    }
    let mut operations: Vec<&'static str> = Vec::new();
    for operation in KEYED_MAP_OPERATIONS {
        if receivers
            .iter()
            .any(|(receiver, ranges): (&String, &BTreeSet<TextRange>)| {
                ranges.iter().any(|range: &TextRange| {
                    let source: &str = scoped_source(&compact, range);
                    contains_receiver_operation(source, receiver, operation)
                        || contains_associated_receiver_operation(source, receiver, operation)
                })
            })
        {
            operations.push(operation);
        }
    }
    if receivers
        .iter()
        .any(|(receiver, ranges): (&String, &BTreeSet<TextRange>)| {
            ranges.iter().any(|range: &TextRange| {
                contains_receiver_index(scoped_source(&compact, range), receiver)
            })
        })
    {
        operations.push("index");
    }
    if receivers
        .iter()
        .any(|(receiver, ranges): (&String, &BTreeSet<TextRange>)| {
            let assignment: Regex =
                Regex::new(&format!(r"(?:^|[^A-Za-z0-9_]){}=", regex::escape(receiver)))
                    .expect("metadata assignment pattern");
            ranges
                .iter()
                .any(|range: &TextRange| assignment.is_match(scoped_source(&compact, range)))
        })
    {
        operations.push("assignment");
    }
    let map_replacement: Regex = Regex::new(
        r"(?:std::)?mem::replace\(&mut((?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.)+metadata),",
    )
    .expect("metadata replacement pattern");
    if map_replacement
        .captures_iter(&compact)
        .any(|captures: regex::Captures<'_>| {
            captures.get(1).is_some_and(|receiver: regex::Match<'_>| {
                scoped_metadata_receiver_is_owned(
                    receiver.as_str(),
                    receiver.start(),
                    &owner_bindings,
                )
            })
        })
    {
        operations.push("replacement");
    }
    let map_take: Regex = Regex::new(
        r"(?:std::)?mem::take\(&mut((?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\.)+metadata)\)",
    )
    .expect("metadata take pattern");
    if map_take
        .captures_iter(&compact)
        .any(|captures: regex::Captures<'_>| {
            captures.get(1).is_some_and(|receiver: regex::Match<'_>| {
                scoped_metadata_receiver_is_owned(
                    receiver.as_str(),
                    receiver.start(),
                    &owner_bindings,
                )
            })
        })
    {
        operations.push("take");
    }
    let map_swap: Regex =
        Regex::new(r"(?:std::)?mem::swap\(([^,]+),([^\)]*)\)").expect("metadata swap pattern");
    if map_swap
        .captures_iter(&compact)
        .any(|captures: regex::Captures<'_>| {
            [captures.get(1), captures.get(2)]
                .into_iter()
                .flatten()
                .map(|argument: regex::Match<'_>| {
                    (
                        argument
                            .as_str()
                            .strip_prefix("&mut")
                            .unwrap_or(argument.as_str()),
                        argument.start(),
                    )
                })
                .any(|(receiver, position): (&str, usize)| {
                    receiver.ends_with(".metadata")
                        && scoped_metadata_receiver_is_owned(receiver, position, &owner_bindings)
                })
        })
    {
        operations.push("swap");
    }
    if receivers
        .iter()
        .any(|(receiver, ranges): (&String, &BTreeSet<TextRange>)| {
            ranges.iter().any(|range: &TextRange| {
                let source: &str = scoped_source(&compact, range);
                source.contains(&format!("metadata_keys::get(&{receiver},"))
                    || source.contains(&format!("metadata_keys::get({receiver},"))
            })
        })
    {
        operations.push("compatibility-get");
    }
    if receivers
        .iter()
        .any(|(receiver, ranges): (&String, &BTreeSet<TextRange>)| {
            let parsed: Regex = Regex::new(&format!(
                r"metadata_keys::get_parsed(?:::<[^>]+>)?\((?:&)?{},",
                regex::escape(receiver)
            ))
            .expect("compatibility parsed getter pattern");
            ranges
                .iter()
                .any(|range: &TextRange| parsed.is_match(scoped_source(&compact, range)))
        })
    {
        operations.push("compatibility-get-parsed");
    }
    let local_construction: Regex =
        Regex::new(r"let(?:mut)?metadata(?::[^=;]+)?=BTreeMap::(?:from|from_iter)\(")
            .expect("local metadata construction pattern");
    if compact.contains("metadata:BTreeMap::from(")
        || compact.contains("metadata:BTreeMap::from_iter(")
        || compact.contains("metadata:collect::<BTreeMap<String,String>>(")
        || returning_map_uses_raw_construction(&compact, &functions, returning_functions)
        || receivers
            .get("metadata")
            .is_some_and(|ranges: &BTreeSet<TextRange>| {
                ranges.iter().any(|range: &TextRange| {
                    local_construction.is_match(scoped_source(&compact, range))
                })
            })
    {
        operations.push("construction");
    }
    operations
}

fn probe_metadata_key_accesses(source: &str) -> Vec<&'static str> {
    let targets: MetadataFunctionTargets = metadata_targeted_functions([("probe.rs", source)]);
    let metadata_functions: BTreeSet<String> = targets
        .by_source
        .get("probe.rs")
        .cloned()
        .unwrap_or_default();
    let returning_functions: BTreeSet<String> = targets
        .returning_by_source
        .get("probe.rs")
        .cloned()
        .unwrap_or_default();
    direct_metadata_key_accesses(source, &metadata_functions, &returning_functions)
}

fn contains_associated_receiver_operation(source: &str, receiver: &str, operation: &str) -> bool {
    ["", "&", "&mut"].iter().any(|prefix: &&str| {
        [',', ')'].iter().any(|suffix: &char| {
            source.contains(&format!("BTreeMap::{operation}{prefix}{receiver}{suffix}"))
        })
    })
}

fn contains_receiver_index(source: &str, receiver: &str) -> bool {
    let needle: String = format!("{receiver}[");
    source
        .match_indices(&needle)
        .any(|(index, _matched): (usize, &str)| {
            index == 0
                || source
                    .as_bytes()
                    .get(index.saturating_sub(1))
                    .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_')
        })
}

fn contains_receiver_operation(source: &str, receiver: &str, operation: &str) -> bool {
    let needle: String = format!("{receiver}.{operation}");
    source
        .match_indices(&needle)
        .any(|(index, _matched): (usize, &str)| {
            index == 0
                || source
                    .as_bytes()
                    .get(index.saturating_sub(1))
                    .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_')
        })
}

fn allowlisted_direct_access(path: &Path, source: &str, operation: &str) -> bool {
    if operation != "clone(" || !path.ends_with("crates/disrobe-core/src/chain/chain_json.rs") {
        return false;
    }
    let compact: String = code_only(source)
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect();
    compact.matches("metadata:n.metadata.clone(),").count() == 1
        && compact.matches(".metadata.clone(").count() == 1
}

#[test]
fn literal_and_computed_metadata_keys_are_rejected_by_the_probe() {
    let literal: &str = "let mut metadata: BTreeMap<String, String> = BTreeMap::new(); metadata.insert(\"family.key\".to_string(), value); Artifact { metadata, bytes }";
    let computed: &str = "node.metadata.insert(build_key(input), value);";
    let alias: &str = "let map = &mut node.metadata; map.insert(build_key(input), value);";
    let renamed: &str = "fn write(values: &mut BTreeMap<String, String>) { values.insert(build_key(input), value); } fn run(node: &mut Node) { write(&mut node.metadata); }";
    let constructed: &str = "metadata: BTreeMap::from([(build_key(input), value)])";
    let associated: &str =
        "let values = &mut node.metadata; BTreeMap::insert(values, build_key(input), value);";
    let indexed: &str = "let value = node.metadata[build_key(input)];";
    let nested_indexed: &str = "nodes[0].metadata.insert(build_key(input), value);";
    let destructured: &str =
        "let Node { metadata: values, .. } = node; values.insert(build_key(input), value);";
    let replaced: &str = "node.metadata = BTreeMap::from([(build_key(input), value)]);";
    assert_eq!(probe_metadata_key_accesses(literal), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(computed), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(alias), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(renamed), vec!["insert("]);
    assert_eq!(
        probe_metadata_key_accesses(constructed),
        vec!["construction"]
    );
    assert_eq!(probe_metadata_key_accesses(associated), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(indexed), vec!["index"]);
    assert_eq!(probe_metadata_key_accesses(nested_indexed), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(destructured), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(replaced), vec!["assignment"]);
}

#[test]
fn whole_map_access_and_compatibility_apis_are_rejected() {
    let cases: [(&str, &str); 26] = [
        ("node.metadata = replacement;", "assignment"),
        ("let copy = node.metadata.clone();", "clone("),
        ("node.metadata.clone_from(&replacement);", "clone_from("),
        (
            "std::mem::replace(&mut node.metadata, replacement);",
            "replacement",
        ),
        ("std::mem::take(&mut node.metadata);", "take"),
        ("std::mem::swap(&mut detached, &mut node.metadata);", "swap"),
        ("std::mem::swap(&mut node.metadata, &mut detached);", "swap"),
        ("node.metadata.clear();", "clear("),
        ("node.metadata.pop_first();", "pop_first("),
        ("node.metadata.pop_last();", "pop_last("),
        ("node.metadata.iter();", "iter("),
        ("node.metadata.keys();", "keys("),
        ("node.metadata.into_iter();", "into_iter("),
        ("node.metadata.into_keys();", "into_keys("),
        ("node.metadata.into_values();", "into_values("),
        ("node.metadata.len();", "len("),
        ("node.metadata.is_empty();", "is_empty("),
        ("node.metadata.first_entry();", "first_entry("),
        ("node.metadata.last_entry();", "last_entry("),
        ("node.metadata.first_key_value();", "first_key_value("),
        ("node.metadata.last_key_value();", "last_key_value("),
        ("BTreeMap::into_iter(node.metadata);", "into_iter("),
        ("BTreeMap::len(&node.metadata);", "len("),
        ("BTreeMap::is_empty(&node.metadata);", "is_empty("),
        (
            "metadata_keys::get(&node.metadata, \"literal.key\");",
            "compatibility-get",
        ),
        (
            "metadata_keys::get_parsed::<usize>(&node.metadata, build_key());",
            "compatibility-get-parsed",
        ),
    ];
    for (source, expected) in cases {
        assert_eq!(
            probe_metadata_key_accesses(source),
            vec![expected],
            "{source}"
        );
    }
}

#[test]
fn only_the_chain_json_wire_copy_is_allowlisted() {
    let path: &Path = Path::new("crates/disrobe-core/src/chain/chain_json.rs");
    let serializer: &str = "Self { metadata: n.metadata.clone(), verdict }";
    assert!(allowlisted_direct_access(path, serializer, "clone("));
    assert!(!allowlisted_direct_access(
        path,
        "Self { metadata: node.metadata.clone(), verdict }",
        "clone("
    ));
    assert!(!allowlisted_direct_access(
        path,
        "Self { metadata: n.metadata.clone(), other: node.metadata.clone() }",
        "clone("
    ));
    assert!(!allowlisted_direct_access(
        Path::new("crates/other/src/chain_json.rs"),
        serializer,
        "clone("
    ));
}

#[test]
fn metadata_helper_reachability_is_transitive_through_typed_aliases() {
    let source: &str = "fn leaf(out: &mut BTreeMap<String, String>) { out.insert(build_key(), value); } fn middle(out: &mut BTreeMap<String, String>) { leaf(out); } fn top(out: &mut BTreeMap<String, String>) { middle(out); } fn run(nodes: &mut [Node], index: usize) { let selected: &mut Node = &mut nodes[index]; let values: &mut BTreeMap<String, String> = &mut selected.metadata; top(values); } fn unrelated(headers: &mut BTreeMap<String, String>) { top(headers); headers.insert(name, value); }";
    let targets: MetadataFunctionTargets = metadata_targeted_functions([("probe.rs", source)]);
    assert_eq!(
        targets.by_source.get("probe.rs"),
        Some(&BTreeSet::from([
            "leaf".to_string(),
            "middle".to_string(),
            "top".to_string()
        ]))
    );
    assert_eq!(
        direct_metadata_key_accesses(
            source,
            targets.by_source.get("probe.rs").expect("metadata helpers"),
            &BTreeSet::new(),
        ),
        vec!["insert("]
    );
    assert!(targets.ambiguous.is_empty());
}

#[test]
fn pass_outcome_metadata_roots_and_helpers_are_rejected() {
    let direct: &str =
        "fn run(outcome: &mut PassRunOutcome) { outcome.metadata.insert(build_key(), value); }";
    let helper: &str = "fn write<'a>(values: &'a mut BTreeMap<String, String>) { values.remove(build_key()); } fn run(outcomes: &mut [PassRunOutcome], index: usize) { write(&mut outcomes[index].metadata); }";
    let local: &str = "fn run() -> PassRunOutcome { let mut metadata: BTreeMap<String, String> = BTreeMap::new(); metadata.insert(build_key(), value); PassRunOutcome { metadata, ..fallback() } }";
    assert_eq!(probe_metadata_key_accesses(direct), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(helper), vec!["remove("]);
    assert_eq!(probe_metadata_key_accesses(local), vec!["insert("]);
}

#[test]
fn local_metadata_roots_taint_helpers_and_returned_maps() {
    let local_helper: &str = "fn fill(values: &mut BTreeMap<String, String>) { values.insert(build_key(), value); } fn run() -> PassRunOutcome { let mut output: BTreeMap<String, String> = BTreeMap::new(); fill(&mut output); PassRunOutcome { metadata: output, ..fallback() } }";
    let returned: &str = "fn build() -> BTreeMap<String, String> { let mut output: BTreeMap<String, String> = BTreeMap::new(); output.insert(build_key(), value); output } fn run() -> Node { Node { metadata: build(), ..fallback() } }";
    let inferred: &str = "fn build() -> BTreeMap<String, String> { let mut output = BTreeMap::new(); output.insert(build_key(), value); output } fn run() -> Node { Node { metadata: build(), ..fallback() } }";
    let constructed: &str = "fn build() -> BTreeMap<String, String> { BTreeMap::from([(build_key(), value)]) } fn run() -> Node { Node { metadata: build(), ..fallback() } }";
    let transitive: &str = "fn leaf() -> BTreeMap<String, String> { let mut output = BTreeMap::new(); output.insert(build_key(), value); output } fn build() -> BTreeMap<String, String> { leaf() } fn run() -> Node { Node { metadata: build(), ..fallback() } }";
    let local_targets: MetadataFunctionTargets =
        metadata_targeted_functions([("probe.rs", local_helper)]);
    assert_eq!(
        local_targets.by_source.get("probe.rs"),
        Some(&BTreeSet::from(["fill".to_string()]))
    );
    let returned_targets: MetadataFunctionTargets =
        metadata_targeted_functions([("probe.rs", returned)]);
    assert_eq!(
        returned_targets.returning_by_source.get("probe.rs"),
        Some(&BTreeSet::from(["build".to_string()]))
    );
    assert_eq!(probe_metadata_key_accesses(local_helper), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(returned), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(inferred), vec!["insert("]);
    assert_eq!(
        probe_metadata_key_accesses(constructed),
        vec!["construction"]
    );
    assert_eq!(probe_metadata_key_accesses(transitive), vec!["insert("]);
}

#[test]
fn shorthand_alias_constructor_and_nested_metadata_roots_are_rejected() {
    let shorthand: &str = "fn run(node: Node) { let Node { metadata, .. } = node; metadata.insert(build_key(), value); }";
    let alias: &str = "type MetadataMap<'a> = BTreeMap<String, String>; fn write<'a>(values: &'a mut MetadataMap<'a>) { values.insert(build_key(), value); } fn run(node: &mut Node) { write(&mut node.metadata); }";
    let constructed: &str = "type MetadataMap = BTreeMap<String, String>; fn run(bytes: Vec<u8>) -> Node { let metadata: MetadataMap = BTreeMap::from([(build_key(), value)]); Node { metadata, bytes } }";
    let nested: &str = "fn run(outcomes: &mut [PassRunOutcome], index: usize) { outcomes[index].metadata.insert(build_key(), value); }";
    let nested_owner: &str =
        "fn run(wrapper: &mut Wrapper) { wrapper.outcome.metadata.insert(build_key(), value); }";
    assert_eq!(probe_metadata_key_accesses(shorthand), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(alias), vec!["insert("]);
    assert_eq!(
        probe_metadata_key_accesses(constructed),
        vec!["construction"]
    );
    assert_eq!(probe_metadata_key_accesses(nested), vec!["insert("]);
    assert_eq!(probe_metadata_key_accesses(nested_owner), vec!["insert("]);
}

#[test]
fn chain_owner_type_aliases_are_metadata_roots() {
    for source in [
        "type ChainNode = Node; fn run(node: &mut ChainNode) { node.metadata.insert(build_key(), value); }",
        "type ChainOutcome = PassRunOutcome; fn run(outcome: &mut ChainOutcome) { outcome.metadata.insert(build_key(), value); }",
    ] {
        assert_eq!(probe_metadata_key_accesses(source), vec!["insert("]);
    }
}

#[test]
fn inferred_nodes_require_a_chain_plan_receiver() {
    let unrelated: &str = "fn write(values: &mut BTreeMap<String, String>) { values.insert(build_key(), value); } fn run(plan: &HttpPlan) { for node in &plan.nodes { write(&mut node.metadata); } }";
    let chain: &str = "fn write(values: &mut BTreeMap<String, String>) { values.insert(build_key(), value); } fn run(plan: &ChainPlan) { for node in &plan.nodes { write(&mut node.metadata); } }";
    assert!(
        !metadata_targeted_functions([("probe.rs", unrelated)])
            .by_source
            .contains_key("probe.rs")
    );
    assert_eq!(
        metadata_targeted_functions([("probe.rs", chain)])
            .by_source
            .get("probe.rs"),
        Some(&BTreeSet::from(["write".to_string()]))
    );
}

#[test]
fn metadata_map_aliases_apply_across_source_files() {
    let declaration: &str = "type SharedMetadata<'a> = BTreeMap<String, String>;";
    let helper: &str =
        "fn write<'a>(values: &'a mut SharedMetadata<'a>) { values.insert(build_key(), value); }";
    let aliases: BTreeSet<String> = metadata_map_aliases(declaration);
    let metadata_functions: BTreeSet<String> = BTreeSet::from(["write".to_string()]);
    assert_eq!(
        direct_metadata_key_accesses_with_aliases(
            helper,
            &metadata_functions,
            &BTreeSet::new(),
            &aliases,
        ),
        vec!["insert("]
    );
}

#[test]
fn comments_and_literals_do_not_create_metadata_usage_or_accesses() {
    let source: &str = r####"
        // node.metadata.insert(build_key(), value);
        /* metadata_keys::set_comma_list(&mut node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &["cff"]); */
        const NORMAL: &str = "node.metadata.clone(); metadata_keys::get_comma_list(&node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY);";
        const RAW: &str = r###"node.metadata.into_values(); metadata_keys::set_comma_list(&mut node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &[])"###;
        fn live(node: &mut Node) { metadata_keys::get_comma_list(&node.metadata, keys::LIVE_KEY); }
    "####;
    assert!(probe_metadata_key_accesses(source).is_empty());
    let usage: BTreeMap<String, KeyUsage> = key_usage_in_sources([source]);
    assert_eq!(usage.len(), 1);
    assert_eq!(
        usage.get("LIVE_KEY"),
        Some(&KeyUsage {
            reads: 1,
            writes: 0
        })
    );
}

#[test]
fn ordered_metadata_key_apis_are_rejected_by_the_probe() {
    let range: &str = "node.metadata.range(build_key()..).next();";
    let range_mut: &str = "node.metadata.range_mut(build_key()..).next();";
    let split_off: &str = "node.metadata.split_off(&build_key());";
    let lower_bound: &str = "node.metadata.lower_bound(Bound::Included(&build_key()));";
    let upper_bound: &str = "node.metadata.upper_bound(Bound::Excluded(&build_key()));";
    assert_eq!(probe_metadata_key_accesses(range), vec!["range("]);
    assert_eq!(probe_metadata_key_accesses(range_mut), vec!["range_mut("]);
    assert_eq!(probe_metadata_key_accesses(split_off), vec!["split_off("]);
    assert_eq!(
        probe_metadata_key_accesses(lower_bound),
        vec!["lower_bound("]
    );
    assert_eq!(
        probe_metadata_key_accesses(upper_bound),
        vec!["upper_bound("]
    );
}

#[test]
fn metadata_helpers_called_from_another_source_are_rejected() {
    let helper: &str =
        "fn write(out: &mut BTreeMap<String, String>) { out.insert(build_key(), value); }";
    let caller: &str = "fn run(node: &mut Node) { write(&mut node.metadata); }";
    let targets: MetadataFunctionTargets =
        metadata_targeted_functions([("helpers.rs", helper), ("runner.rs", caller)]);
    let metadata_functions: BTreeSet<String> = targets
        .by_source
        .get("helpers.rs")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        direct_metadata_key_accesses(helper, &metadata_functions, &BTreeSet::new()),
        vec!["insert("]
    );
    assert!(targets.ambiguous.is_empty());
}

#[test]
fn qualified_helper_calls_do_not_taint_same_named_unrelated_maps() {
    let chain: &str =
        "fn write(out: &mut BTreeMap<String, String>) { out.insert(build_key(), value); }";
    let headers: &str =
        "fn write(headers: &mut BTreeMap<String, String>) { headers.insert(name, value); }";
    let caller: &str = "fn run(node: &mut Node) { chain::write(&mut node.metadata); }";
    let targets: MetadataFunctionTargets = metadata_targeted_functions([
        ("chain.rs", chain),
        ("headers.rs", headers),
        ("runner.rs", caller),
    ]);
    let chain_functions: BTreeSet<String> = targets
        .by_source
        .get("chain.rs")
        .cloned()
        .unwrap_or_default();
    let header_functions: BTreeSet<String> = targets
        .by_source
        .get("headers.rs")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        direct_metadata_key_accesses(chain, &chain_functions, &BTreeSet::new()),
        vec!["insert("]
    );
    assert!(direct_metadata_key_accesses(headers, &header_functions, &BTreeSet::new()).is_empty());
    assert!(targets.ambiguous.is_empty());
}

#[test]
fn lexical_helper_provenance_distinguishes_modules_and_impls() {
    let modules: &str = "mod chain { fn write(out: &mut BTreeMap<String, String>) { out.insert(build_key(), value); } fn run(node: &mut Node) { write(&mut node.metadata); } } mod headers { fn write(out: &mut BTreeMap<String, String>) { out.remove(name); } }";
    let module_targets: MetadataFunctionTargets =
        metadata_targeted_functions([("same.rs", modules)]);
    assert_eq!(
        module_targets.by_source.get("same.rs"),
        Some(&BTreeSet::from(["chain::write".to_string()]))
    );
    assert_eq!(
        direct_metadata_key_accesses(
            modules,
            module_targets
                .by_source
                .get("same.rs")
                .expect("module targets"),
            &BTreeSet::new(),
        ),
        vec!["insert("]
    );

    let implementations: &str = "impl Chain { fn write(out: &mut BTreeMap<String, String>) { out.insert(build_key(), value); } fn run(node: &mut Node) { Self::write(&mut node.metadata); } } impl Headers { fn write(out: &mut BTreeMap<String, String>) { out.remove(name); } }";
    let impl_targets: MetadataFunctionTargets =
        metadata_targeted_functions([("same.rs", implementations)]);
    assert_eq!(
        impl_targets.by_source.get("same.rs"),
        Some(&BTreeSet::from(["Chain::write".to_string()]))
    );
    assert_eq!(
        direct_metadata_key_accesses(
            implementations,
            impl_targets.by_source.get("same.rs").expect("impl targets"),
            &BTreeSet::new(),
        ),
        vec!["insert("]
    );
}

#[test]
fn source_after_a_test_cfg_is_still_enforced() {
    let source: &str = "#[cfg(test)] fn fixture() {} fn write(node: &mut Node) { node.metadata.insert(build_key(), value); }";
    let production: String = without_test_cfg_items(source);
    assert_eq!(probe_metadata_key_accesses(&production), vec!["insert("]);
    assert!(!production.contains("fixture"));
}

#[test]
fn structural_test_cfg_forms_are_excluded_without_truncation() {
    for attribute in [
        "#[cfg ( test )]",
        "#[cfg(any(test))]",
        "#[cfg(all(windows, test))]",
        "#[cfg(any(all(test), all(test, windows)))]",
    ] {
        let source: String = format!(
            "{attribute} fn fixture(node: &mut Node) {{ node.metadata.insert(build_key(), value); }} fn after(node: &mut Node) {{ metadata_keys::set_string(&mut node.metadata, keys::AFTER_KEY, value); }}"
        );
        let production: String = without_test_cfg_items(&source);
        assert!(!production.contains("fixture"), "{attribute}");
        assert!(production.contains("fn after"), "{attribute}");
        assert!(
            probe_metadata_key_accesses(&production).is_empty(),
            "{attribute}"
        );
    }
}

#[test]
fn test_cfg_text_inside_a_literal_does_not_hide_later_source() {
    let source: &str = r##"const MARKER: &str = "#[cfg(test)]"; fn write(node: &mut Node) { node.metadata.insert(build_key(), value); }"##;
    let production: String = without_test_cfg_items(source);
    assert_eq!(production, source);
    assert_eq!(probe_metadata_key_accesses(&production), vec!["insert("]);
}

#[test]
fn test_only_writes_do_not_mask_a_production_dead_read() {
    let source: &str = "fn read(metadata: &BTreeMap<String, String>) { metadata_keys::get_comma_list(metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY); } fn run(node: &mut Node) { read(&node.metadata); } #[cfg(test)] fn fixture(metadata: &mut BTreeMap<String, String>) { metadata_keys::set_comma_list(metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &[\"value\"]); } fn after() {}";
    let production: String = without_test_cfg_items(source);
    let usage: BTreeMap<String, KeyUsage> = key_usage_in_sources([production.as_str()]);
    assert_eq!(
        usage.get("ANTI_RECOVERED_TECHNIQUES_KEY"),
        Some(&KeyUsage {
            reads: 1,
            writes: 0
        })
    );
    assert!(production.contains("fn after()"));
}

#[test]
fn metadata_usage_resolves_module_and_symbol_aliases() {
    let source: &str = "use disrobe_core::chain::metadata_keys as mk; use disrobe_core::chain::metadata_keys::set_comma_list; use disrobe_core::chain::metadata_keys::keys::ANTI_RECOVERED_TECHNIQUES_KEY as TECHNIQUES; fn run(node: &mut Node) { mk::get_comma_list(&node.metadata, TECHNIQUES); set_comma_list(&mut node.metadata, TECHNIQUES, &[\"cff\"]); }";
    let usage: BTreeMap<String, KeyUsage> = key_usage_in_sources([source]);
    assert_eq!(
        usage.get("ANTI_RECOVERED_TECHNIQUES_KEY"),
        Some(&KeyUsage {
            reads: 1,
            writes: 1
        })
    );
}

#[test]
fn typed_metadata_usage_requires_a_chain_metadata_receiver() {
    let source: &str = "fn unrelated(headers: &mut BTreeMap<String, String>) { metadata_keys::set_comma_list(headers, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &[\"value\"]); } fn unrelated_node(node: &mut HttpNode) { metadata_keys::get_comma_list(&node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY); } fn unrelated_plan(plan: &HttpPlan) { for node in &plan.nodes { metadata_keys::get_comma_list(&node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY); } } fn computed(node: &mut Node) { metadata_keys::get_comma_list(&node.metadata, make_key(keys::ANTI_RECOVERED_TECHNIQUES_KEY), &[\"value\"]); } fn run(node: &mut Node) { metadata_keys::get_comma_list(&node.metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY); }";
    let usage: BTreeMap<String, KeyUsage> = key_usage_in_sources([source]);
    assert_eq!(
        usage.get("ANTI_RECOVERED_TECHNIQUES_KEY"),
        Some(&KeyUsage {
            reads: 1,
            writes: 0
        })
    );
}

#[test]
fn typed_accessor_import_forms_are_exempt_from_direct_access_enforcement() {
    let source: &str = "use disrobe_core::chain::metadata_keys as mk; use disrobe_core::chain::metadata_keys::set_comma_list; use disrobe_core::chain::metadata_keys::get_comma_list as read_list; fn run(node: &mut Node) { mk::get_comma_list(&node.metadata, keys::FIRST_KEY); set_comma_list(&mut node.metadata, keys::SECOND_KEY, &[\"cff\"]); read_list(&node.metadata, keys::THIRD_KEY); }";
    let targets: MetadataFunctionTargets = metadata_targeted_functions([("probe.rs", source)]);
    assert!(targets.ambiguous.is_empty());
    assert!(probe_metadata_key_accesses(source).is_empty());
}

#[test]
fn typed_accessor_imports_do_not_exempt_sibling_module_helpers() {
    let source: &str = "mod typed { use disrobe_core::chain::metadata_keys::set_string; fn run(node: &mut Node) { set_string(&mut node.metadata, keys::TEXT_KEY, \"value\"); } } mod raw { fn set_string(values: &mut BTreeMap<String, String>) { values.insert(build_key(), value); } fn run(node: &mut Node) { set_string(&mut node.metadata); } }";
    let targets: MetadataFunctionTargets = metadata_targeted_functions([("probe.rs", source)]);
    assert_eq!(
        targets.by_source.get("probe.rs"),
        Some(&BTreeSet::from(["raw::set_string".to_string()]))
    );
    assert_eq!(probe_metadata_key_accesses(source), vec!["insert("]);
}

#[test]
fn unrelated_string_maps_are_not_metadata_violations() {
    let method: &str =
        "let mut headers: BTreeMap<String, String> = BTreeMap::new(); headers.insert(name, value);";
    let associated: &str = "BTreeMap::insert(headers, name, value);";
    let constructed: &str = "let headers = BTreeMap::from([(name, value)]);";
    assert!(probe_metadata_key_accesses(method).is_empty());
    assert!(probe_metadata_key_accesses(associated).is_empty());
    assert!(probe_metadata_key_accesses(constructed).is_empty());
}

#[test]
fn metadata_receiver_provenance_is_function_scoped() {
    let reused_binding: &str = "fn run() -> PassRunOutcome { let values: BTreeMap<String, String> = BTreeMap::new(); PassRunOutcome { metadata: values, ..fallback() } } fn unrelated() { let mut values: BTreeMap<String, String> = BTreeMap::new(); values.insert(name, value); }";
    let unrelated_node: &str =
        "fn update(node: &mut HttpNode) { node.metadata.insert(name, value); }";
    let unrelated_take: &str =
        "fn update(node: &mut HttpNode) { std::mem::take(&mut node.metadata); }";
    assert!(probe_metadata_key_accesses(reused_binding).is_empty());
    assert!(probe_metadata_key_accesses(unrelated_node).is_empty());
    assert!(probe_metadata_key_accesses(unrelated_take).is_empty());
}

#[test]
fn repository_scan_discovers_rust_sources_without_a_file_allowlist() {
    let root: PathBuf = repository_root();
    let sources: Vec<PathBuf> = rust_source_paths(&root.join("crates"));
    assert!(sources.contains(&root.join("crates/disrobe-core/src/chain/detection.rs")));
    assert!(sources.contains(&root.join("crates/disrobe-cli/src/cli/chain_v1.rs")));
    assert!(sources.contains(&root.join("crates/disrobe-mcp/src/chain.rs")));
    assert!(sources.len() > 7);
}

#[test]
fn registered_metadata_keys_have_classified_reads_and_writes() {
    let root: PathBuf = repository_root();
    let usage: BTreeMap<String, KeyUsage> = registered_key_usage(&root);
    let registered: &[RegisteredKey] = registered_keys();
    let names: BTreeSet<&str> = registered
        .iter()
        .map(|key: &RegisteredKey| key.name())
        .collect();
    assert_eq!(
        names.len(),
        registered.len(),
        "registered wire names must be unique"
    );
    let symbols: BTreeSet<&str> = registered
        .iter()
        .map(|key: &RegisteredKey| key.symbol())
        .collect();
    let unregistered: Vec<&str> = usage
        .keys()
        .map(String::as_str)
        .filter(|symbol: &&str| !symbols.contains(symbol))
        .collect();
    let unused: Vec<&str> = symbols
        .iter()
        .copied()
        .filter(|symbol: &&str| !usage.contains_key(*symbol))
        .collect();
    let dead_reads: Vec<&str> = usage
        .iter()
        .filter(|(_symbol, counts): &(&String, &KeyUsage)| counts.reads > 0 && counts.writes == 0)
        .map(|(symbol, _counts): (&String, &KeyUsage)| symbol.as_str())
        .collect();
    assert!(
        unregistered.is_empty(),
        "typed keys missing from registry: {unregistered:?}"
    );
    assert!(
        unused.is_empty(),
        "registered metadata keys are unused: {unused:?}"
    );
    assert!(
        dead_reads.is_empty(),
        "metadata keys read but never written: {dead_reads:?}"
    );
    let anti_usage: &KeyUsage = usage
        .get("ANTI_RECOVERED_TECHNIQUES_KEY")
        .expect("registered key usage");
    assert!(anti_usage.reads > 0);
    assert!(anti_usage.writes > 0);
    let unpublished_writes: Vec<&str> = registered
        .iter()
        .filter(|key: &&RegisteredKey| {
            usage
                .get(key.symbol())
                .is_some_and(|counts: &KeyUsage| counts.writes > 0)
                && !key.published()
        })
        .map(|key: &RegisteredKey| key.symbol())
        .collect();
    assert!(
        unpublished_writes.is_empty(),
        "metadata keys written to Node must be published: {unpublished_writes:?}"
    );
}

#[test]
fn production_metadata_keys_are_routed_through_the_registry() {
    let root: PathBuf = repository_root();
    let mut violations: Vec<String> = Vec::new();
    let mut sources: Vec<(PathBuf, String, String)> = Vec::new();
    for path in rust_source_paths(&root.join("crates")) {
        if !path
            .components()
            .any(|component| component.as_os_str() == "src")
            || path.ends_with("crates/disrobe-core/src/chain/metadata_keys.rs")
        {
            continue;
        }
        let source: String =
            std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
                panic!("failed to read {}: {error}", path.display())
            });
        let source_id: String = path
            .strip_prefix(&root)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .into_owned();
        sources.push((path, source_id, without_test_cfg_items(&source)));
    }
    let targets: MetadataFunctionTargets = metadata_targeted_functions(
        sources
            .iter()
            .map(|(_path, source_id, source)| (source_id.as_str(), source.as_str())),
    );
    for ambiguous in &targets.ambiguous {
        violations.push(format!("ambiguous-metadata-helper:{ambiguous}"));
    }
    let known_map_aliases: BTreeSet<String> = sources
        .iter()
        .flat_map(|(_path, _source_id, source): &(PathBuf, String, String)| {
            metadata_map_aliases(source)
        })
        .collect();
    for (path, source_id, source) in sources {
        let metadata_functions: BTreeSet<String> = targets
            .by_source
            .get(&source_id)
            .cloned()
            .unwrap_or_default();
        let returning_functions: BTreeSet<String> = targets
            .returning_by_source
            .get(&source_id)
            .cloned()
            .unwrap_or_default();
        for operation in direct_metadata_key_accesses_with_aliases(
            &source,
            &metadata_functions,
            &returning_functions,
            &known_map_aliases,
        ) {
            let relative_path: &Path = path.strip_prefix(&root).unwrap_or(path.as_path());
            if allowlisted_direct_access(relative_path, &source, operation) {
                continue;
            }
            violations.push(format!("{}:{operation}", relative_path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "metadata key access must use metadata_keys: {violations:?}"
    );
}
