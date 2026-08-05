use std::collections::BTreeSet;

use crate::structurize::{TargetLang, csharp_escape_identifier, is_simple_identifier};

fn is_managed_byref_type(ty: &str) -> bool {
    ty.starts_with("ref ") || ty.starts_with("byref<") || ty.starts_with("ByRef ")
}

#[must_use]
pub fn positional_parameter_name(index: usize) -> String {
    format!("arg{}", index.saturating_add(1))
}

#[must_use]
pub fn is_positional_parameter_name(name: &str) -> bool {
    name.strip_prefix("arg").is_some_and(|digits: &str| {
        !digits.is_empty() && digits.bytes().all(|byte: u8| byte.is_ascii_digit())
    })
}

#[must_use]
pub fn csharp_parameter_name(name: &str, index: usize) -> String {
    if let Some(suffix) = name.strip_prefix("<>h__TransparentIdentifier")
        && !suffix.is_empty()
        && suffix.bytes().all(|byte: u8| byte.is_ascii_digit())
    {
        return format!("transparentIdentifier{suffix}");
    }
    if is_simple_identifier(name) {
        return csharp_escape_identifier(name);
    }
    if name.strip_prefix('@').is_some_and(is_simple_identifier) {
        return name.to_owned();
    }
    if let Some(readable) = compiler_generated_parameter_name(name) {
        return readable;
    }
    positional_parameter_name(index)
}

fn compiler_generated_parameter_name(name: &str) -> Option<String> {
    let rest: &str = name.strip_prefix('<')?;
    let close: usize = rest.find('>')?;
    let inner: &str = rest.get(..close)?;
    let after: &str = rest.get(close.saturating_add(1)..)?;
    let core: &str = if inner.is_empty() {
        let digits: usize = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let tail: &str = after.get(digits..)?;
        let underscores: usize = tail.bytes().take_while(|byte: &u8| *byte == b'_').count();
        if underscores < 2 {
            return None;
        }
        tail.get(underscores..)?
    } else {
        inner
    };
    if !is_simple_identifier(core) {
        return None;
    }
    let mut chars: std::str::Chars<'_> = core.chars();
    let first: char = chars.next()?;
    let lowered: String = first.to_ascii_lowercase().to_string() + chars.as_str();
    Some(csharp_escape_identifier(&lowered))
}

#[must_use]
pub fn canonical_parameter_names(raw: &[String], lang: TargetLang) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (index, name) in raw.iter().enumerate() {
        let base: String = match lang {
            TargetLang::CSharp => csharp_parameter_name(name, index),
            TargetLang::FSharp | TargetLang::VbNet => {
                if is_simple_identifier(name) {
                    name.clone()
                } else {
                    positional_parameter_name(index)
                }
            }
        };
        let mut candidate: String = base.clone();
        let mut suffix: usize = 2;
        while !used.insert(candidate.clone()) {
            candidate = format!("{base}_{suffix}");
            suffix = suffix.saturating_add(1);
        }
        out.push(candidate);
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct NameTable {
    has_this: bool,
    param_names: Vec<String>,
    param_types: Vec<String>,
    local_types: Vec<String>,
}

impl NameTable {
    #[must_use]
    pub const fn new(
        has_this: bool,
        param_names: Vec<String>,
        param_types: Vec<String>,
        local_types: Vec<String>,
    ) -> Self {
        Self {
            has_this,
            param_names,
            param_types,
            local_types,
        }
    }

    #[must_use]
    pub const fn has_this(&self) -> bool {
        self.has_this
    }

    #[must_use]
    pub fn arg_name(&self, slot: u32) -> String {
        let idx: usize = (slot as usize).wrapping_sub(1);
        self.param_names
            .get(idx)
            .filter(|n: &&String| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("arg{slot}"))
    }

    #[must_use]
    pub fn param_names(&self) -> &[String] {
        &self.param_names
    }

    #[must_use]
    pub fn arg_type(&self, slot: u32) -> Option<&str> {
        let idx: usize = (slot as usize).wrapping_sub(1);
        self.param_types.get(idx).map(String::as_str)
    }

    #[must_use]
    pub fn arg_is_managed_byref(&self, slot: u32) -> bool {
        self.arg_type(slot).is_some_and(is_managed_byref_type)
    }

    #[must_use]
    pub fn local_is_managed_byref(&self, slot: u32) -> bool {
        self.local_type(slot).is_some_and(is_managed_byref_type)
    }

    #[must_use]
    pub fn local_name(slot: u32) -> String {
        format!("local{slot}")
    }

    #[must_use]
    pub fn local_type(&self, slot: u32) -> Option<&str> {
        self.local_types.get(slot as usize).map(String::as_str)
    }

    #[must_use]
    pub fn typed_locals_count(&self, used: &[u32]) -> u32 {
        used.iter()
            .filter(|slot: &&u32| self.local_type(**slot).is_some())
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn named_params_count(&self) -> u32 {
        self.param_names
            .iter()
            .filter(|n: &&String| !n.is_empty() && !is_positional_parameter_name(n))
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn local_decl(&self, slot: u32, lang: TargetLang) -> String {
        let name: String = Self::local_name(slot);
        match (self.local_type(slot), lang) {
            (Some(ty), TargetLang::CSharp) => format!("{ty} {name};"),
            (None, TargetLang::CSharp) => format!("var {name};"),
            (Some(ty), TargetLang::FSharp) => {
                format!("let mutable {name} : {ty} = Unchecked.defaultof<_>")
            }
            (None, TargetLang::FSharp) => {
                format!("let mutable {name} = Unchecked.defaultof<_>")
            }
            (Some(ty), TargetLang::VbNet) => format!("Dim {name} As {ty}"),
            (None, TargetLang::VbNet) => format!("Dim {name}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn csharp_parameter_name_recovers_transparent_identifiers_and_refuses_invalid_metadata() {
        assert_eq!(
            csharp_parameter_name("<>h__TransparentIdentifier12", 0),
            "transparentIdentifier12"
        );
        assert_eq!(csharp_parameter_name("bad-name", 1), "arg2");
        assert_eq!(csharp_parameter_name("class", 2), "@class");
    }

    #[test]
    fn csharp_parameter_name_reads_a_compiler_generated_metadata_name() {
        assert_eq!(csharp_parameter_name("<>1__state", 0), "state");
        assert_eq!(csharp_parameter_name("<>2__current", 0), "current");
        assert_eq!(csharp_parameter_name("<>7__wrap1", 0), "wrap1");
        assert_eq!(
            csharp_parameter_name("<Length>k__BackingField", 0),
            "length"
        );
        assert_eq!(csharp_parameter_name("<>1__object", 0), "@object");
    }

    #[test]
    fn compiler_generated_parameter_name_refuses_a_shape_it_cannot_read() {
        for name in [
            "state",
            "<>1state",
            "<>__state",
            "<>1__",
            "<>1__two words",
            "<>1__9leading",
            "<unclosed",
            "<>",
            "",
        ] {
            assert_eq!(compiler_generated_parameter_name(name), None, "{name}");
        }
    }

    #[test]
    fn csharp_parameter_names_are_deterministically_unique() {
        let names: Vec<String> = canonical_parameter_names(
            &[
                "transparentIdentifier0".to_owned(),
                "<>h__TransparentIdentifier0".to_owned(),
                "arg4".to_owned(),
                "bad-name".to_owned(),
            ],
            TargetLang::CSharp,
        );
        assert_eq!(
            names,
            [
                "transparentIdentifier0",
                "transparentIdentifier0_2",
                "arg4",
                "arg4_2",
            ]
        );
    }

    #[test]
    fn an_empty_metadata_name_becomes_a_positional_name_in_every_language() {
        for lang in [TargetLang::CSharp, TargetLang::FSharp, TargetLang::VbNet] {
            assert_eq!(
                canonical_parameter_names(
                    &[String::new(), "count".to_owned(), String::new()],
                    lang
                ),
                ["arg1", "count", "arg3"],
                "{lang:?}"
            );
        }
    }

    #[test]
    fn every_canonical_name_is_a_usable_identifier() {
        let raw: Vec<String> = vec![
            String::new(),
            "<>1__state".to_owned(),
            "bad-name".to_owned(),
            "\u{202e}".to_owned(),
            "9leading".to_owned(),
            "@object".to_owned(),
        ];
        for lang in [TargetLang::CSharp, TargetLang::FSharp, TargetLang::VbNet] {
            for name in canonical_parameter_names(&raw, lang) {
                let core: &str = name.strip_prefix('@').unwrap_or(&name);
                let base: &str = core.rsplit_once('_').map_or(core, |(head, _)| head);
                assert!(
                    is_simple_identifier(core) || is_simple_identifier(base),
                    "{lang:?} produced an unusable identifier {name:?}"
                );
            }
        }
    }

    #[test]
    fn arg_name_uses_recovered_param_name() {
        let t: NameTable = NameTable::new(
            false,
            vec!["start".to_owned(), "count".to_owned()],
            vec!["int".to_owned(), "int".to_owned()],
            Vec::new(),
        );
        assert_eq!(t.arg_name(1), "start");
        assert_eq!(t.arg_name(2), "count");
    }

    #[test]
    fn arg_name_falls_back_when_unnamed() {
        let t: NameTable = NameTable::new(
            false,
            vec![String::new()],
            vec!["int".to_owned()],
            Vec::new(),
        );
        assert_eq!(t.arg_name(1), "arg1");
        assert_eq!(t.arg_name(5), "arg5");
    }

    #[test]
    fn local_decl_csharp_carries_type() {
        let t: NameTable = NameTable::new(
            false,
            Vec::new(),
            Vec::new(),
            vec!["double".to_owned(), "int[]".to_owned()],
        );
        assert_eq!(t.local_decl(0, TargetLang::CSharp), "double local0;");
        assert_eq!(t.local_decl(1, TargetLang::CSharp), "int[] local1;");
    }

    #[test]
    fn local_decl_falls_back_to_var_when_untyped() {
        let t: NameTable = NameTable::default();
        assert_eq!(t.local_decl(0, TargetLang::CSharp), "var local0;");
        assert_eq!(
            t.local_decl(0, TargetLang::FSharp),
            "let mutable local0 = Unchecked.defaultof<_>"
        );
        assert_eq!(t.local_decl(0, TargetLang::VbNet), "Dim local0");
    }
}
