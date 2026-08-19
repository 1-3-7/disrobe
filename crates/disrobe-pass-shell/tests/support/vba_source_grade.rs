use std::path::{Path, PathBuf};

pub(crate) fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .parent()
        .and_then(|p: &Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

pub(crate) fn read_corpus(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(relative);
    std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", path.display()))
}

pub(crate) fn read_authored(relative: &str) -> String {
    let path: PathBuf = corpus_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", path.display()))
}

pub(crate) fn strip_trailing_comment(line: &str) -> &str {
    let mut in_string: bool = false;
    for (index, byte) in line.as_bytes().iter().enumerate() {
        match byte {
            b'"' => in_string = !in_string,
            b'\'' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

pub(crate) fn normalize(line: &str) -> String {
    let source: &str = strip_trailing_comment(line);
    let mut out: String = String::with_capacity(source.len());
    let mut in_string: bool = false;
    let mut pending_space: bool = false;
    for ch in source.chars() {
        if in_string {
            out.push(ch);
            if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push('"');
            in_string = true;
            continue;
        }
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch.to_ascii_lowercase());
    }
    out
}

pub(crate) fn ends_with_continuation(line: &str) -> bool {
    let trimmed: &str = line.trim_end();
    let Some(head) = trimmed.strip_suffix('_') else {
        return false;
    };
    head.is_empty() || head.ends_with(char::is_whitespace)
}

pub(crate) fn join_continuations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let head: &str = if ends_with_continuation(raw) {
            raw.trim_end()
                .strip_suffix('_')
                .expect("continuation suffix checked")
                .trim_end()
        } else {
            raw
        };
        let merged: String = pending.take().map_or_else(
            || head.to_owned(),
            |mut acc: String| {
                acc.push(' ');
                acc.push_str(head.trim_start());
                acc
            },
        );
        if ends_with_continuation(raw) {
            pending = Some(merged);
        } else {
            out.push(merged);
        }
    }
    if let Some(acc) = pending {
        out.push(acc);
    }
    out
}

pub(crate) fn code_lines(text: &str) -> Vec<String> {
    join_continuations(text)
        .into_iter()
        .map(|l: String| normalize(&l))
        .filter(|l: &String| !l.is_empty() && !l.starts_with("attribute "))
        .collect()
}

fn align_in_order(authored: &[String], recovered: &[String]) -> Vec<Option<usize>> {
    let rows: usize = authored.len();
    let cols: usize = recovered.len();
    let stride: usize = cols + 1;
    let mut table: Vec<u32> = vec![0_u32; (rows + 1) * stride];
    for a in (0..rows).rev() {
        for r in (0..cols).rev() {
            let cell: u32 = if authored[a] == recovered[r] {
                table[(a + 1) * stride + r + 1] + 1
            } else {
                table[(a + 1) * stride + r].max(table[a * stride + r + 1])
            };
            table[a * stride + r] = cell;
        }
    }
    let mut mapping: Vec<Option<usize>> = vec![None; rows];
    let mut a: usize = 0;
    let mut r: usize = 0;
    while a < rows && r < cols {
        if authored[a] == recovered[r] {
            mapping[a] = Some(r);
            a += 1;
            r += 1;
        } else if table[(a + 1) * stride + r] >= table[a * stride + r + 1] {
            a += 1;
        } else {
            r += 1;
        }
    }
    mapping
}

pub(crate) struct Grade {
    pub(crate) matched: usize,
    pub(crate) total: usize,
    pub(crate) line_match_pct: f64,
    pub(crate) first_mismatch: Option<Mismatch>,
}

pub(crate) struct Mismatch {
    pub(crate) authored_ordinal: usize,
    pub(crate) authored: String,
    pub(crate) recovered: String,
}

pub(crate) fn grade(recovered: &str, authored: &str) -> Grade {
    grade_lines(&code_lines(authored), &code_lines(recovered))
}

pub(crate) fn grade_lines(auth_lines: &[String], rec_lines: &[String]) -> Grade {
    let mapping: Vec<Option<usize>> = align_in_order(auth_lines, rec_lines);

    let matched: usize = mapping
        .iter()
        .filter(|m: &&Option<usize>| m.is_some())
        .count();
    let mut first_mismatch: Option<Mismatch> = None;
    let mut cursor: usize = 0;
    for (index, slot) in mapping.iter().enumerate() {
        match slot {
            Some(r) => cursor = r + 1,
            None => {
                if first_mismatch.is_none() {
                    first_mismatch = Some(Mismatch {
                        authored_ordinal: index + 1,
                        authored: auth_lines[index].clone(),
                        recovered: rec_lines
                            .get(cursor)
                            .cloned()
                            .unwrap_or_else(|| "<past end of recovered source>".to_owned()),
                    });
                }
            }
        }
    }

    Grade {
        matched,
        total: auth_lines.len(),
        line_match_pct: 100.0 * matched as f64 / auth_lines.len().max(1) as f64,
        first_mismatch,
    }
}

pub(crate) fn assert_line_match(label: &str, grade: &Grade, floor_pct: f64, expected_total: usize) {
    let detail: String = grade.first_mismatch.as_ref().map_or_else(
        || "every authored line matched in order".to_owned(),
        |m: &Mismatch| {
            format!(
                "first unmatched authored line {}\n  authored:  {}\n  recovered: {}",
                m.authored_ordinal, m.authored, m.recovered
            )
        },
    );
    println!(
        "{label}: in-order line match {:.2}% ({}/{})\n{label}: {detail}",
        grade.line_match_pct, grade.matched, grade.total
    );
    assert_eq!(
        grade.total, expected_total,
        "{label} authored code-line count changed; the match rate denominator is pinned so a \
         shrinking fixture cannot raise the rate"
    );
    assert!(
        grade.line_match_pct >= floor_pct,
        "{label} in-order line match {:.2}% below floor {floor_pct:.2}% ({}/{})\n{detail}",
        grade.line_match_pct,
        grade.matched,
        grade.total
    );
}
