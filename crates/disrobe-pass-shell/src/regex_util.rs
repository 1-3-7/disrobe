use regex::Regex;

#[allow(clippy::expect_used)]
pub(crate) fn safe_regex(pattern: &str) -> Regex {
    Regex::new(pattern)
        .unwrap_or_else(|_| Regex::new("$.^").expect("trivial never-matching regex must compile"))
}

pub(crate) fn first_capture<'h>(cap: &regex::Captures<'h>, idxs: &[usize]) -> &'h str {
    for &i in idxs {
        if let Some(m) = cap.get(i) {
            return m.as_str();
        }
    }
    ""
}
