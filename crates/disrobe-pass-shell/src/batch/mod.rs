use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub random_substitutions: usize,
    pub set_substitutions: usize,
    pub output: String,
}

static SET_DECL: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?im)^\s*set\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<val>[^\r\n]*)"#,
    )
});

static RAND_RANGE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"%random:~(\d+),(\d+)%"));

static RAND_PLAIN: LazyLock<Regex> = LazyLock::new(|| crate::regex_util::safe_regex(r"%random%"));

static VAR_REF: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"%(?P<name>[A-Za-z_][A-Za-z0-9_]*)%"));

#[must_use]
pub fn reverse_batch(input: &str) -> BatchReport {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for cap in SET_DECL.captures_iter(input) {
        let Some(n) = cap.name("name") else {
            continue;
        };
        let v: String = cap
            .name("val")
            .map(|m: regex::Match<'_>| m.as_str().trim().to_owned())
            .unwrap_or_default();
        env.insert(n.as_str().to_ascii_uppercase(), v);
    }
    let mut current: String = input.to_owned();
    let mut rand_subs: usize = 0;
    current = RAND_RANGE
        .replace_all(&current, |c: &regex::Captures<'_>| {
            rand_subs += 1;
            let len: usize = c
                .get(2)
                .and_then(|m: regex::Match<'_>| m.as_str().parse::<usize>().ok())
                .unwrap_or(1);
            "0".repeat(len)
        })
        .into_owned();
    current = RAND_PLAIN
        .replace_all(&current, |_: &regex::Captures<'_>| {
            rand_subs += 1;
            "0".to_owned()
        })
        .into_owned();
    let mut set_subs: usize = 0;
    for _ in 0..16usize {
        let mut hit: bool = false;
        let next: std::borrow::Cow<'_, str> =
            VAR_REF.replace_all(&current, |c: &regex::Captures<'_>| {
                let Some(name) = c.name("name") else {
                    return c
                        .get(0)
                        .map_or(String::new(), |m: regex::Match<'_>| m.as_str().to_owned());
                };
                let key: String = name.as_str().to_ascii_uppercase();
                env.get(&key).map_or_else(
                    || {
                        c.get(0)
                            .map_or(String::new(), |m: regex::Match<'_>| m.as_str().to_owned())
                    },
                    |v: &String| {
                        hit = true;
                        set_subs += 1;
                        v.clone()
                    },
                )
            });
        let next_owned: String = next.into_owned();
        if !hit || next_owned == current {
            current = next_owned;
            break;
        }
        current = next_owned;
    }
    BatchReport {
        random_substitutions: rand_subs,
        set_substitutions: set_subs,
        output: current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_set_indirection() {
        let src: &str = "@echo off\nset CMD=whoami\n%CMD%\n";
        let r: BatchReport = reverse_batch(src);
        assert!(r.output.contains("whoami"));
        assert!(r.set_substitutions >= 1);
    }

    #[test]
    fn replaces_random_with_zero() {
        let src: &str = "@echo off\nset X=%random%-%random:~0,3%\n";
        let r: BatchReport = reverse_batch(src);
        assert!(r.output.contains("0-000"));
        assert!(r.random_substitutions >= 2);
    }
}
