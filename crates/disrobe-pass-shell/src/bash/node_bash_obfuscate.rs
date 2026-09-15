use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NodeBashObfuscateReport {
    pub chunk_count: usize,
    pub line_count: usize,
    pub chunk_size: usize,
    pub steps: Vec<String>,
    pub walls: Vec<String>,
    pub output: String,
}

const MAX_TABLE_ENTRIES: usize = 200_000;
const MAX_RECOVERED_OUTPUT: usize = 32 * 1024 * 1024;
const SEPARATOR_VAR: &str = "z";

static HEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex("(?m)^\\s*z=\"\\n?\\s*\";"));

static EVAL_TRAILER: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex("(?s)\\beval\\s+\"((?:\\$[A-Za-z][A-Za-z0-9]*)+)\"\\s*$")
});

static CHUNK_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex("[A-Za-z][A-Za-z0-9]*z='"));

#[must_use]
pub fn is_node_bash_obfuscate(input: &str) -> bool {
    let trimmed: &str = input.trim_start_matches(['\u{feff}', '\n', '\r', ' ', '\t']);
    if !trimmed.starts_with("z=\"") {
        return false;
    }
    let header_ok: bool = trimmed.contains("z=\"\n\";") || trimmed.contains("z=\"\r\n\";");
    if !header_ok {
        return false;
    }
    if EVAL_TRAILER.is_match(trimmed) {
        return true;
    }
    CHUNK_ASSIGN.find_iter(trimmed).take(3).count() >= 3
}

#[must_use]
pub fn reverse_node_bash_obfuscate(input: &str) -> Option<NodeBashObfuscateReport> {
    let body: &str = input.trim_start_matches(['\u{feff}', '\n', '\r', ' ', '\t']);
    let header: regex::Match<'_> = HEADER.find(body)?;
    let eval: regex::Captures<'_> = EVAL_TRAILER.captures(body)?;
    let eval_full: regex::Match<'_> = eval.get(0)?;
    let table_region: &str = &body[header.end()..eval_full.start()];
    let references: &str = eval.get(1)?.as_str();

    let mut steps: Vec<String> = Vec::new();
    let mut walls: Vec<String> = Vec::new();
    let (table, table_steps): (BTreeMap<String, String>, usize) = parse_chunk_table(table_region);
    if table.is_empty() {
        return None;
    }
    steps.push(format!("parse-chunk-table:{table_steps}"));

    let mut out: String = String::with_capacity(references.len());
    let mut line_count: usize = 1;
    let mut max_chunk_len: usize = 0;
    let mut unresolved: usize = 0;
    let ref_bytes: &[u8] = references.as_bytes();
    let mut i: usize = 0;
    while i < ref_bytes.len() {
        if ref_bytes[i] != b'$' {
            return None;
        }
        let name_start: usize = i + 1;
        let mut name_end: usize = name_start;
        while name_end < ref_bytes.len() && ref_bytes[name_end].is_ascii_alphanumeric() {
            name_end += 1;
        }
        let name: &str = &references[name_start..name_end];
        if name == SEPARATOR_VAR {
            out.push('\n');
            line_count += 1;
        } else if let Some(chunk) = table.get(name) {
            max_chunk_len = max_chunk_len.max(chunk.chars().count());
            out.push_str(chunk);
        } else {
            unresolved += 1;
        }
        if out.len() > MAX_RECOVERED_OUTPUT {
            walls.push(format!(
                "recovered output exceeds {MAX_RECOVERED_OUTPUT}-byte ceiling; recovery halted"
            ));
            break;
        }
        i = name_end;
    }
    if unresolved > 0 {
        walls.push(format!(
            "{unresolved} eval references had no matching chunk-table entry; recovery incomplete"
        ));
    }
    steps.push(format!("substitute-chunks:{}", table.len()));
    if max_chunk_len > 0 {
        steps.push(format!("infer-chunk-size:{max_chunk_len}"));
    }
    Some(NodeBashObfuscateReport {
        chunk_count: table.len(),
        line_count,
        chunk_size: max_chunk_len,
        steps,
        walls,
        output: out,
    })
}

fn parse_chunk_table(region: &str) -> (BTreeMap<String, String>, usize) {
    let bytes: &[u8] = region.as_bytes();
    let mut table: BTreeMap<String, String> = BTreeMap::new();
    let mut entries: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() && entries < MAX_TABLE_ENTRIES {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b';') {
            i += 1;
        }
        let name_start: usize = i;
        while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if i == name_start || i >= bytes.len() || bytes[i] != b'=' {
            i = name_start + 1;
            continue;
        }
        let name: &str = &region[name_start..i];
        i += 1;
        if i >= bytes.len() || bytes[i] != b'\'' {
            continue;
        }
        i += 1;
        let Some((value, next)): Option<(String, usize)> = read_single_quoted(region, i) else {
            continue;
        };
        i = next;
        table.insert(name.to_owned(), value);
        entries += 1;
    }
    (table, entries)
}

fn read_single_quoted(region: &str, start: usize) -> Option<(String, usize)> {
    let bytes: &[u8] = region.as_bytes();
    let mut out: String = String::new();
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'\\')
                && bytes.get(i + 2) == Some(&b'\'')
                && bytes.get(i + 3) == Some(&b'\'')
            {
                out.push('\'');
                i += 4;
                continue;
            }
            return Some((out, i + 1));
        }
        let ch_len: usize = utf8_char_len(bytes[i]);
        let end: usize = (i + ch_len).min(bytes.len());
        out.push_str(&region[i..end]);
        i = end;
    }
    None
}

fn utf8_char_len(first: u8) -> usize {
    match first {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        b if b >> 3 == 0b11110 => 4,
        _ => 1,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const REAL_C4: &str =
        include_str!("../../../../corpus/shell/bash/node-bash-obfuscate/obfuscated_chunk4.sh");

    #[test]
    fn detects_node_bash_obfuscate_signature() {
        assert!(is_node_bash_obfuscate(REAL_C4));
        assert!(!is_node_bash_obfuscate("#!/bin/bash\necho hi\n"));
        assert!(!is_node_bash_obfuscate("z=\"hello\";echo $z"));
    }

    #[test]
    fn recovers_real_obfuscated_script() {
        let r: NodeBashObfuscateReport =
            reverse_node_bash_obfuscate(REAL_C4).expect("recovery present");
        assert!(r.walls.is_empty(), "walls={:?}", r.walls);
        let expected: &str = "GREETING='hello world'\necho \"$GREETING\"\nfor i in 1 2 3; do\necho \"line $i\"\ndone\nprintf 'done:%s\\n' \"$GREETING\"";
        assert_eq!(r.output, expected, "recovered:\n{}", r.output);
        assert_eq!(r.line_count, 6);
        assert_eq!(r.chunk_count, 26);
    }

    #[test]
    fn single_quote_escape_round_trips() {
        let (table, _): (BTreeMap<String, String>, usize) = parse_chunk_table("Az='it'\\''s';");
        assert_eq!(table.get("Az").map(String::as_str), Some("it's"));
    }
}
