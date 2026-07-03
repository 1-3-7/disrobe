const MAX_ROTATIONS: u32 = 4096;

pub(super) fn simulate(
    strings: &[String],
    _pivot_index: usize,
    pivot_value: i64,
) -> (Vec<String>, u32) {
    if strings.is_empty() {
        return (strings.to_vec(), 0);
    }
    let mut current: Vec<String> = strings.to_vec();
    for k in 0..=MAX_ROTATIONS {
        if matches_pivot(&current, pivot_value) {
            return (current, k);
        }
        current.rotate_left(1);
    }
    (strings.to_vec(), 0)
}

fn matches_pivot(strings: &[String], pivot: i64) -> bool {
    let Some(first): Option<&String> = strings.first() else {
        return false;
    };
    if let Ok(n) = first.parse::<i64>() {
        return n == pivot;
    }
    if let Some(stripped) = first.strip_prefix("0x")
        && let Ok(n) = i64::from_str_radix(stripped, 16)
    {
        return n == pivot;
    }
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_array_returns_unchanged() {
        let (out, k): (Vec<String>, u32) = simulate(&[], 0, 1);
        assert!(out.is_empty());
        assert_eq!(k, 0);
    }

    #[test]
    fn first_element_already_matches_pivot() {
        let arr: Vec<String> = vec!["1".to_owned(), "x".to_owned()];
        let (_out, k): (Vec<String>, u32) = simulate(&arr, 0, 1);
        assert_eq!(k, 0);
    }

    #[test]
    fn rotation_finds_pivot_at_offset() {
        let arr: Vec<String> = vec!["a".to_owned(), "b".to_owned(), "1".to_owned()];
        let (out, k): (Vec<String>, u32) = simulate(&arr, 0, 1);
        assert_eq!(k, 2);
        assert_eq!(out.first(), Some(&"1".to_owned()));
    }

    #[test]
    fn no_match_returns_original() {
        let arr: Vec<String> = vec!["hi".to_owned(), "world".to_owned()];
        let (out, k): (Vec<String>, u32) = simulate(&arr, 0, 42);
        assert_eq!(k, 0);
        assert_eq!(out, arr);
    }
}
