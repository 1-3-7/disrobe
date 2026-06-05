use serde::{Deserialize, Serialize};

/// Library-privacy hash separator from Dart `String::kPrivateKeySeparator`.
const PRIVATE_KEY_SEPARATOR: char = '@';
const GETTER_PREFIX: &str = "get:";
const SETTER_PREFIX: &str = "set:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartNameKind {
    Getter,
    Setter,
    Constructor,
    NamedConstructor,
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemangledName {
    pub scrubbed: String,
    pub kind: DartNameKind,
    pub is_private: bool,
}

/// Demangles a Dart AOT internal name to its scrubbed, source-visible form.
#[must_use]
pub fn demangle(internal: &str) -> DemangledName {
    let (body, kind): (&str, DartNameKind) =
        if let Some(rest) = internal.strip_prefix(GETTER_PREFIX) {
            (rest, DartNameKind::Getter)
        } else if let Some(rest) = internal.strip_prefix(SETTER_PREFIX) {
            (rest, DartNameKind::Setter)
        } else {
            (internal, DartNameKind::Method)
        };

    let is_private: bool = body.contains(PRIVATE_KEY_SEPARATOR) || body.starts_with('_');
    let without_hash: String = strip_privacy_hashes(body);

    let (scrubbed, final_kind): (String, DartNameKind) =
        if let Some(stripped) = without_hash.strip_suffix('.') {
            (stripped.to_owned(), DartNameKind::Constructor)
        } else if without_hash.contains('.') && matches!(kind, DartNameKind::Method) {
            (without_hash, DartNameKind::NamedConstructor)
        } else {
            (without_hash, kind)
        };

    DemangledName {
        scrubbed,
        kind: final_kind,
        is_private,
    }
}

/// Removes every `@<hash>` library-privacy suffix from a name.
#[must_use]
fn strip_privacy_hashes(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == PRIVATE_KEY_SEPARATOR {
            while let Some(&next) = chars.peek() {
                if next == '.' {
                    break;
                }
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Demangles a fully qualified `Library_Class_method` AOT symbol into dotted form.
#[must_use]
pub fn demangle_qualified(symbol: &str) -> String {
    let demangled: DemangledName = demangle(symbol);
    demangled.scrubbed
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn private_getter() {
        let d: DemangledName = demangle("get:foo@6be832b");
        assert_eq!(d.scrubbed, "foo");
        assert_eq!(d.kind, DartNameKind::Getter);
        assert!(d.is_private);
    }

    #[test]
    fn private_setter() {
        let d: DemangledName = demangle("set:value@abc123");
        assert_eq!(d.scrubbed, "value");
        assert_eq!(d.kind, DartNameKind::Setter);
    }

    #[test]
    fn unnamed_constructor() {
        let d: DemangledName = demangle("_MyClass@6b3832b.");
        assert_eq!(d.scrubbed, "_MyClass");
        assert_eq!(d.kind, DartNameKind::Constructor);
        assert!(d.is_private);
    }

    #[test]
    fn named_constructor() {
        let d: DemangledName = demangle("_MyClass@6b3832b.named");
        assert_eq!(d.scrubbed, "_MyClass.named");
        assert_eq!(d.kind, DartNameKind::NamedConstructor);
    }

    #[test]
    fn public_method_unchanged() {
        let d: DemangledName = demangle("build");
        assert_eq!(d.scrubbed, "build");
        assert_eq!(d.kind, DartNameKind::Method);
        assert!(!d.is_private);
    }

    #[test]
    fn core_impl_class_preserved() {
        let d: DemangledName = demangle("_OneByteString");
        assert_eq!(d.scrubbed, "_OneByteString");
        assert!(d.is_private);
    }

    #[test]
    fn qualified_helper_scrubs_hash() {
        assert_eq!(demangle_qualified("get:length@1a2b3c"), "length");
    }
}
