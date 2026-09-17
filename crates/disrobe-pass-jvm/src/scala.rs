use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Demangled {
    pub original: String,
    pub demangled: String,
}

#[must_use]
pub fn demangle(name: &str) -> Demangled {
    let no_dollar_suffix: &str = name.strip_suffix('$').unwrap_or(name);
    let parts: Vec<&str> = no_dollar_suffix.split('$').collect();
    let mut decoded: Vec<String> = Vec::with_capacity(parts.len());
    let mut i: usize = 0;
    while i < parts.len() {
        let p: &str = parts[i];
        if p.is_empty() {
            i += 1;
            continue;
        }
        if let Some(replacement) = scala_op_decode(p) {
            decoded.push(replacement.to_string());
        } else {
            decoded.push(p.to_string());
        }
        i += 1;
    }
    let demangled: String = decoded.join(".");
    Demangled {
        original: name.to_string(),
        demangled,
    }
}

const SCALA_OPS: &[(&str, &str)] = &[
    ("tilde", "~"),
    ("eq", "="),
    ("less", "<"),
    ("greater", ">"),
    ("bang", "!"),
    ("hash", "#"),
    ("percent", "%"),
    ("up", "^"),
    ("amp", "&"),
    ("bar", "|"),
    ("times", "*"),
    ("div", "/"),
    ("plus", "+"),
    ("minus", "-"),
    ("colon", ":"),
    ("bslash", "\\"),
    ("qmark", "?"),
    ("at", "@"),
];

fn scala_op_decode(token: &str) -> Option<&'static str> {
    SCALA_OPS
        .iter()
        .find_map(|(k, v)| (*k == token).then_some(*v))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn demangle_simple_object_suffix() {
        let d: Demangled = demangle("Foo$");
        assert_eq!(d.demangled, "Foo");
    }

    #[test]
    fn demangle_operator_token() {
        let d: Demangled = demangle("Foo$plus$plus");
        assert!(d.demangled.contains('+'));
    }

    #[test]
    fn demangle_empty_returns_empty() {
        let d: Demangled = demangle("");
        assert!(d.demangled.is_empty());
    }
}
