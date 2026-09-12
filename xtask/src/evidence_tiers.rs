pub(crate) fn cited_test_names(text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (index, token) in text.split_whitespace().enumerate() {
        let cleaned: &str = token.trim_matches(|c: char| c == '`' || c == '|' || c == ',');
        if let Some(stem) = cleaned.strip_suffix(".rs")
            && let Some((_, file)) = stem.rsplit_once('/')
        {
            names.push(file.to_owned());
        }
        if index > 0
            && text.split_whitespace().nth(index - 1) == Some("--test")
            && !cleaned.is_empty()
        {
            names.push(cleaned.to_owned());
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

pub(crate) fn row_metric(line: &str) -> String {
    line.trim_matches('|')
        .split('|')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_metric_extracts_first_cell() {
        assert_eq!(
            row_metric("| JVM classfile | 131 / 131 `recompile-only` | real javac | tests/x.rs |"),
            "JVM classfile"
        );
    }
}
