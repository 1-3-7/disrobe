const NATIVE_BUILTINS_HBC76: &[&str] = &[
    "Array.isArray",
    "ArrayBuffer.isView",
    "Date.UTC",
    "Date.now",
    "Date.parse",
    "JSON.parse",
    "JSON.stringify",
    "Math.abs",
    "Math.acos",
    "Math.asin",
    "Math.atan",
    "Math.atan2",
    "Math.ceil",
    "Math.cos",
    "Math.exp",
    "Math.floor",
    "Math.hypot",
    "Math.imul",
    "Math.log",
    "Math.max",
    "Math.min",
    "Math.pow",
    "Math.random",
    "Math.round",
    "Math.sin",
    "Math.sqrt",
    "Math.tan",
    "Math.trunc",
    "Object.create",
    "Object.defineProperties",
    "Object.defineProperty",
    "Object.freeze",
    "Object.getOwnPropertyDescriptor",
    "Object.getOwnPropertyNames",
    "Object.getPrototypeOf",
    "Object.isExtensible",
    "Object.isFrozen",
    "Object.keys",
    "Object.seal",
    "String.fromCharCode",
];

const NATIVE_BUILTINS_HBC96: &[&str] = &[
    "Array.isArray",
    "Date.UTC",
    "Date.parse",
    "JSON.parse",
    "JSON.stringify",
    "Math.abs",
    "Math.acos",
    "Math.asin",
    "Math.atan",
    "Math.atan2",
    "Math.ceil",
    "Math.cos",
    "Math.exp",
    "Math.floor",
    "Math.hypot",
    "Math.imul",
    "Math.log",
    "Math.max",
    "Math.min",
    "Math.pow",
    "Math.round",
    "Math.sin",
    "Math.sqrt",
    "Math.tan",
    "Math.trunc",
    "Object.create",
    "Object.defineProperties",
    "Object.defineProperty",
    "Object.freeze",
    "Object.getOwnPropertyDescriptor",
    "Object.getOwnPropertyNames",
    "Object.getPrototypeOf",
    "Object.isExtensible",
    "Object.isFrozen",
    "Object.keys",
    "Object.seal",
    "String.fromCharCode",
];

const GET_TEMPLATE_OBJECT_PRIVATE_INDEX: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BuiltinTable {
    pub version: u32,
    pub methods: &'static [&'static str],
    pub upstream_tag: &'static str,
}

pub(crate) const BUILTIN_TABLES: &[BuiltinTable] = &[
    BuiltinTable {
        version: 76,
        methods: NATIVE_BUILTINS_HBC76,
        upstream_tag: "v0.7.2",
    },
    BuiltinTable {
        version: 84,
        methods: NATIVE_BUILTINS_HBC76,
        upstream_tag: "v0.11.0",
    },
    BuiltinTable {
        version: 96,
        methods: NATIVE_BUILTINS_HBC96,
        upstream_tag: "v0.13.0",
    },
];

#[must_use]
pub(crate) fn builtin_methods(version: u32) -> Option<&'static [&'static str]> {
    BUILTIN_TABLES
        .iter()
        .find(|table: &&BuiltinTable| table.version == version)
        .map(|table: &BuiltinTable| table.methods)
}

#[must_use]
pub fn get_template_object_builtin(version: u32) -> Option<u64> {
    let methods: &'static [&'static str] = builtin_methods(version)?;
    u64::try_from(methods.len())
        .ok()
        .map(|count: u64| count.saturating_add(GET_TEMPLATE_OBJECT_PRIVATE_INDEX))
}

#[must_use]
pub fn builtin_name(version: u32, id: u64) -> String {
    let Some(methods): Option<&'static [&'static str]> = builtin_methods(version) else {
        return format!("$builtin{id}");
    };
    if let Ok(index) = usize::try_from(id)
        && let Some(name) = methods.get(index)
    {
        return (*name).to_owned();
    }
    if get_template_object_builtin(version) == Some(id) {
        return "$getTemplateObject".to_owned();
    }
    format!("$builtin{id}")
}

#[must_use]
pub fn is_template_object_builtin(version: u32, id: u64) -> bool {
    get_template_object_builtin(version) == Some(id)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hermes::HERMES_LIFTED_VERSIONS;

    #[test]
    fn every_lifted_version_carries_a_builtin_table() {
        let registered: Vec<u32> = BUILTIN_TABLES
            .iter()
            .map(|table: &BuiltinTable| table.version)
            .collect();
        assert_eq!(
            registered,
            HERMES_LIFTED_VERSIONS.to_vec(),
            "a lifted version resolves CallBuiltin operands to names, so every version that lifts \
             must carry the builtin table of its own release; a missing table would resolve those \
             operands through another release's numbering and print a name the bundle never called"
        );
    }

    #[test]
    fn the_builtin_numbering_changed_between_the_graded_releases() {
        let v76: &[&str] = builtin_methods(76).expect("hbc v76 builtin table");
        let v84: &[&str] = builtin_methods(84).expect("hbc v84 builtin table");
        let v96: &[&str] = builtin_methods(96).expect("hbc v96 builtin table");

        assert_eq!(
            v76.len(),
            40,
            "include/hermes/FrontEndDefs/Builtins.def at facebook/hermes tag v0.7.2 expands to 40 \
             BUILTIN_METHOD entries"
        );
        assert_eq!(v84.len(), 40, "the same list holds at tag v0.11.0");
        assert_eq!(
            v96.len(),
            37,
            "tag v0.13.0 drops ArrayBuffer.isView, Date.now and Math.random, which renumbers every \
             builtin after the first"
        );
        assert_eq!(v76, v84, "hbc v76 and v84 share one builtin numbering");

        assert_eq!(builtin_name(76, 1), "ArrayBuffer.isView");
        assert_eq!(
            builtin_name(96, 1),
            "Date.UTC",
            "builtin id 1 names a different method at v76 and v96, so resolving one through the \
             other's table prints a call the bundle never made"
        );
        assert_ne!(builtin_name(76, 1), builtin_name(96, 1));

        for dropped in ["ArrayBuffer.isView", "Date.now", "Math.random"] {
            assert!(
                v76.contains(&dropped) && !v96.contains(&dropped),
                "{dropped} is a builtin before hbc v96 and not at v96"
            );
        }
    }

    #[test]
    fn native_builtins_resolve_at_the_reference_version() {
        assert_eq!(builtin_name(96, 0), "Array.isArray");
        assert_eq!(builtin_name(96, 3), "JSON.parse");
        assert_eq!(builtin_name(96, 34), "Object.keys");
        assert_eq!(builtin_name(96, 36), "String.fromCharCode");
    }

    #[test]
    fn the_template_object_builtin_sits_after_the_method_table_of_its_own_release() {
        assert_eq!(get_template_object_builtin(96), Some(39));
        assert_eq!(get_template_object_builtin(84), Some(42));
        assert_eq!(get_template_object_builtin(76), Some(42));
        for version in HERMES_LIFTED_VERSIONS {
            let id: u64 = get_template_object_builtin(version)
                .unwrap_or_else(|| panic!("hbc v{version} states its template-object builtin id"));
            assert!(is_template_object_builtin(version, id), "hbc v{version}");
            assert_eq!(builtin_name(version, id), "$getTemplateObject");
        }
        assert!(
            !is_template_object_builtin(76, 39),
            "id 39 is String.fromCharCode at hbc v76, so reading it as the template-object builtin \
             would rewrite an ordinary call into a template literal"
        );
        assert!(
            !is_template_object_builtin(96, 42),
            "id 42 is not the template-object builtin at hbc v96"
        );
    }

    #[test]
    fn an_unknown_builtin_states_its_number_rather_than_guessing_a_name() {
        for version in HERMES_LIFTED_VERSIONS {
            assert_eq!(builtin_name(version, 200), "$builtin200");
            assert!(!is_template_object_builtin(version, 200));
        }
    }

    #[test]
    fn a_version_with_no_builtin_table_never_prints_a_name_from_another_release() {
        for absent in [0u32, 60, 75, 83, 89, 90, u32::MAX] {
            assert!(builtin_methods(absent).is_none(), "hbc v{absent}");
            assert_eq!(
                builtin_name(absent, 1),
                "$builtin1",
                "hbc v{absent} has no builtin table, so id 1 must stay a number rather than borrow \
                 a name from a release whose numbering may differ"
            );
            assert!(!is_template_object_builtin(absent, 39), "hbc v{absent}");
            assert_eq!(get_template_object_builtin(absent), None);
        }
    }
}
