use super::{Confidence, Context, NameSource, ScopeKey, Suggestion, SymbolRole};

#[derive(Debug, Clone, Default)]
pub struct ContextNameSource;

impl ContextNameSource {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

const STRING_EVIDENCE_CONFIDENCE: Confidence = Confidence(85);

impl NameSource for ContextNameSource {
    fn suggest(&self, _scope: ScopeKey, context: &Context) -> Option<Suggestion> {
        if let Some(s) = context.nearby_strings.iter().find(|s| is_ident_like(s)) {
            return Some(Suggestion {
                name: to_camel_case(s, context.role),
                confidence: STRING_EVIDENCE_CONFIDENCE,
                source_label: self.label(),
            });
        }
        if let Some(assigned) = context.assigned_from.iter().next() {
            return Some(Suggestion {
                name: to_camel_case(semantic_result_role(assigned), context.role),
                confidence: Confidence::LOW,
                source_label: self.label(),
            });
        }
        None
    }

    fn label(&self) -> &'static str {
        "context"
    }
}

fn semantic_result_role(name: &str) -> &str {
    match name {
        "indexOf" => "position",
        _ => name,
    }
}

fn is_ident_like(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars: core::str::Chars<'_> = s.chars();
    let first: char = chars.next().unwrap_or(' ');
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '-' || c == ' ')
}

fn to_camel_case(input: &str, role: SymbolRole) -> String {
    let mut buf: String = String::with_capacity(input.len());
    let mut upper_next: bool = false;
    let mut first: bool = true;
    for ch in input.chars() {
        if ch == '-' || ch == ' ' || ch == '_' {
            upper_next = true;
            continue;
        }
        if first {
            if matches!(role, SymbolRole::Class) {
                buf.extend(ch.to_uppercase());
            } else {
                buf.extend(ch.to_lowercase());
            }
            first = false;
        } else if upper_next {
            buf.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            buf.push(ch);
        }
    }
    if buf.is_empty() {
        return input.to_owned();
    }
    buf
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use crate::mangled_names::ConfidenceTier;

    use super::*;

    #[test]
    fn nearby_string_becomes_suggestion() {
        let src: ContextNameSource = ContextNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Function, ScopeKey(0));
        ctx.nearby_strings.insert("user-login-handler".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("got suggestion");
        assert_eq!(s.name, "userLoginHandler");
        assert_eq!(
            s.confidence.tier(),
            ConfidenceTier::High,
            "a string the author wrote is top-band evidence"
        );
        assert!(
            s.confidence > Confidence::HIGH,
            "a string carries the author's own word, so it must outrank a member-keyword type \
             guess rather than tie with it and be decided by source registration order"
        );
    }

    #[test]
    fn class_role_pascal_cases() {
        let src: ContextNameSource = ContextNameSource::new();
        let mut ctx: Context = Context::new("a", SymbolRole::Class, ScopeKey(0));
        ctx.nearby_strings.insert("user-controller".to_owned());
        let s: Suggestion = src.suggest(ScopeKey(0), &ctx).expect("got suggestion");
        assert_eq!(s.name, "UserController");
    }

    #[test]
    fn no_strings_no_assignments_returns_none() {
        let src: ContextNameSource = ContextNameSource::new();
        let ctx: Context = Context {
            original: "a".into(),
            role: SymbolRole::Variable,
            scope: ScopeKey(0),
            callees: BTreeSet::new(),
            callers: BTreeSet::new(),
            member_accesses: BTreeSet::new(),
            nearby_strings: BTreeSet::new(),
            assigned_from: BTreeSet::new(),
        };
        assert!(src.suggest(ScopeKey(0), &ctx).is_none());
    }
}
