#![cfg(feature = "chain")]
#[derive(Clone, Debug, Default)]
pub(crate) struct GlobMatcher {
    patterns: Vec<String>,
}

impl GlobMatcher {
    pub(crate) fn compile<S: AsRef<str>>(patterns: &[S]) -> Self {
        let patterns: Vec<String> = patterns
            .iter()
            .map(|s: &S| s.as_ref().trim().to_string())
            .filter(|s: &String| !s.is_empty())
            .collect();
        Self { patterns }
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub(crate) fn matches_any(&self, path: &str) -> bool {
        self.patterns.iter().any(|p: &String| matches_one(p, path))
    }
}

fn matches_one(pattern: &str, path: &str) -> bool {
    if glob_match(pattern.as_bytes(), path.as_bytes()) {
        return true;
    }
    if !pattern.contains('/')
        && let Some(basename) = path.rsplit('/').next()
        && glob_match(pattern.as_bytes(), basename.as_bytes())
    {
        return true;
    }
    false
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let width: usize = text.len() + 1;
    let mut memo: Vec<Option<bool>> = vec![None; (pat.len() + 1) * width];
    glob_match_at(pat, text, 0, 0, width, &mut memo)
}

fn glob_match_at(
    pat: &[u8],
    text: &[u8],
    pi: usize,
    ti: usize,
    width: usize,
    memo: &mut [Option<bool>],
) -> bool {
    let key: usize = pi * width + ti;
    if let Some(cached) = memo[key] {
        return cached;
    }
    let result: bool = if pi >= pat.len() {
        ti >= text.len()
    } else {
        match pat[pi] {
            b'*' => {
                let double: bool = pi + 1 < pat.len() && pat[pi + 1] == b'*';
                if double {
                    let rest_pi: usize = {
                        let base: usize = pi + 2;
                        if base < pat.len() && pat[base] == b'/' {
                            base + 1
                        } else {
                            base
                        }
                    };
                    if glob_match_at(pat, text, rest_pi, ti, width, memo) {
                        true
                    } else {
                        let mut hit: bool = false;
                        let mut j: usize = ti + 1;
                        while j <= text.len() {
                            if glob_match_at(pat, text, rest_pi, j, width, memo) {
                                hit = true;
                                break;
                            }
                            j += 1;
                        }
                        hit
                    }
                } else if glob_match_at(pat, text, pi + 1, ti, width, memo) {
                    true
                } else {
                    let mut hit: bool = false;
                    let mut j: usize = ti;
                    while j < text.len() && text[j] != b'/' {
                        if glob_match_at(pat, text, pi + 1, j + 1, width, memo) {
                            hit = true;
                            break;
                        }
                        j += 1;
                    }
                    hit
                }
            }
            b'?' => {
                ti < text.len()
                    && text[ti] != b'/'
                    && glob_match_at(pat, text, pi + 1, ti + 1, width, memo)
            }
            b'[' => {
                let ch: u8 = if ti < text.len() { text[ti] } else { b'/' };
                match class_match(pat, pi, ch) {
                    Some((matched, next_pi)) => {
                        ti < text.len()
                            && matched
                            && glob_match_at(pat, text, next_pi, ti + 1, width, memo)
                    }
                    None => {
                        ti < text.len()
                            && pat[pi] == text[ti]
                            && glob_match_at(pat, text, pi + 1, ti + 1, width, memo)
                    }
                }
            }
            c => {
                ti < text.len()
                    && c == text[ti]
                    && glob_match_at(pat, text, pi + 1, ti + 1, width, memo)
            }
        }
    };
    memo[key] = Some(result);
    result
}

fn class_match(pat: &[u8], start: usize, ch: u8) -> Option<(bool, usize)> {
    debug_assert_eq!(pat[start], b'[');
    let mut i: usize = start + 1;
    let negate: bool = i < pat.len() && (pat[i] == b'!' || pat[i] == b'^');
    if negate {
        i += 1;
    }
    let class_start: usize = i;
    let mut matched: bool = false;
    while i < pat.len() && (pat[i] != b']' || i == class_start) {
        if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
            if pat[i] <= ch && ch <= pat[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= pat.len() || pat[i] != b']' {
        return None;
    }
    Some((matched ^ negate, i + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_does_not_cross_slash() {
        assert!(glob_match(b"*.bin", b"x.bin"));
        assert!(!glob_match(b"*.bin", b"sub/x.bin"));
    }

    #[test]
    fn double_star_crosses_slash() {
        assert!(glob_match(b"**/*.bin", b"sub/dir/x.bin"));
        assert!(glob_match(b"**/*.bin", b"x.bin"));
        assert!(glob_match(b"a/**/z", b"a/b/c/z"));
        assert!(glob_match(b"a/**/z", b"a/z"));
    }

    #[test]
    fn question_matches_single_non_slash() {
        assert!(glob_match(b"f?.txt", b"f1.txt"));
        assert!(!glob_match(b"f?.txt", b"f/.txt"));
    }

    #[test]
    fn char_class_and_negation() {
        assert!(glob_match(b"f[0-9].txt", b"f7.txt"));
        assert!(!glob_match(b"f[0-9].txt", b"fx.txt"));
        assert!(glob_match(b"f[!0-9].txt", b"fx.txt"));
        assert!(!glob_match(b"f[!0-9].txt", b"f7.txt"));
    }

    #[test]
    fn bare_basename_pattern_matches_in_subdir() {
        let m: GlobMatcher = GlobMatcher::compile(&["*.bin"]);
        assert!(m.matches_any("deep/nested/file.bin"));
        assert!(!m.matches_any("deep/nested/file.txt"));
    }

    #[test]
    fn exact_literal_match() {
        assert!(glob_match(b"Cargo.toml", b"Cargo.toml"));
        assert!(!glob_match(b"Cargo.toml", b"cargo.toml"));
    }

    #[test]
    fn empty_matcher_matches_nothing() {
        let m: GlobMatcher = GlobMatcher::compile::<&str>(&[]);
        assert!(m.is_empty());
        assert!(!m.matches_any("anything"));
    }

    #[test]
    fn trailing_star_matches_rest_of_segment() {
        assert!(glob_match(b"pre*", b"prefix"));
        assert!(glob_match(b"pre*", b"pre"));
        assert!(!glob_match(b"pre*", b"pre/fix"));
    }

    #[test]
    fn leading_dirs_with_double_star_suffix() {
        assert!(glob_match(b"build/**", b"build/a/b/c"));
        assert!(glob_match(b"build/**", b"build/x"));
    }

    #[test]
    fn adversarial_star_pattern_stays_bounded() {
        let stars: String = "a*".repeat(40);
        let text: String = "a".repeat(96);
        let mut no_match: String = stars.clone();
        no_match.push('b');
        let start: std::time::Instant = std::time::Instant::now();
        let matched: bool = glob_match(no_match.as_bytes(), text.as_bytes());
        let elapsed: std::time::Duration = start.elapsed();
        assert!(!matched);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "adversarial glob must stay bounded; took {elapsed:?}"
        );
        let mut trailing: String = stars;
        trailing.push('a');
        assert!(glob_match(trailing.as_bytes(), text.as_bytes()));
    }
}
