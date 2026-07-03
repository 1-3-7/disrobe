use crate::structurize::TargetLang;

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
            .filter(|n: &&String| !n.is_empty() && !n.starts_with("arg"))
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
