#[must_use]
pub(crate) fn head(text: &str, max_bytes: usize) -> &str {
    let mut end: usize = text.len().min(max_bytes);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
