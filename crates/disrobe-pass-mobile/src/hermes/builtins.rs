const NATIVE_BUILTINS_HBC62: &[&str] = &[
    "Array.isArray",
    "ArrayBuffer.isView",
    "Date.UTC",
    "Date.now",
    "Date.parse",
    "HermesInternal.getEpilogues",
    "HermesInternal.silentSetPrototypeOf",
    "HermesInternal.requireFast",
    "HermesInternal.getTemplateObject",
    "HermesInternal.ensureObject",
    "HermesInternal.copyDataProperties",
    "HermesInternal.copyRestArgs",
    "HermesInternal.exportAll",
    "HermesInternal.exponentiationOperator",
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

const NATIVE_BUILTINS_HBC71: &[&str] = &[
    "Array.isArray",
    "ArrayBuffer.isView",
    "Date.UTC",
    "Date.now",
    "Date.parse",
    "HermesInternal.getEpilogues",
    "HermesInternal.silentSetPrototypeOf",
    "HermesInternal.requireFast",
    "HermesInternal.getTemplateObject",
    "HermesInternal.ensureObject",
    "HermesInternal.throwTypeError",
    "HermesInternal.generatorSetDelegated",
    "HermesInternal.copyDataProperties",
    "HermesInternal.copyRestArgs",
    "HermesInternal.arraySpread",
    "HermesInternal.apply",
    "HermesInternal.exportAll",
    "HermesInternal.exponentiationOperator",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BuiltinTable {
    pub version: u32,
    pub methods: &'static [&'static str],
    pub template_object_id: u64,
    pub upstream_tag: &'static str,
}

pub(crate) const BUILTIN_TABLES: &[BuiltinTable] = &[
    BuiltinTable {
        version: 62,
        methods: NATIVE_BUILTINS_HBC62,
        template_object_id: 8,
        upstream_tag: "v0.2.1",
    },
    BuiltinTable {
        version: 71,
        methods: NATIVE_BUILTINS_HBC71,
        template_object_id: 8,
        upstream_tag: "v0.3.0",
    },
    BuiltinTable {
        version: 74,
        methods: NATIVE_BUILTINS_HBC76,
        template_object_id: 42,
        upstream_tag: "v0.4.0",
    },
    BuiltinTable {
        version: 76,
        methods: NATIVE_BUILTINS_HBC76,
        template_object_id: 42,
        upstream_tag: "v0.7.2",
    },
    BuiltinTable {
        version: 83,
        methods: NATIVE_BUILTINS_HBC76,
        template_object_id: 42,
        upstream_tag: "v0.8.0",
    },
    BuiltinTable {
        version: 84,
        methods: NATIVE_BUILTINS_HBC76,
        template_object_id: 42,
        upstream_tag: "v0.11.0",
    },
    BuiltinTable {
        version: 89,
        methods: NATIVE_BUILTINS_HBC96,
        template_object_id: 39,
        upstream_tag: "v0.12.0",
    },
    BuiltinTable {
        version: 96,
        methods: NATIVE_BUILTINS_HBC96,
        template_object_id: 39,
        upstream_tag: "v0.13.0",
    },
];

#[must_use]
fn builtin_table(version: u32) -> Option<&'static BuiltinTable> {
    BUILTIN_TABLES
        .iter()
        .find(|table: &&BuiltinTable| table.version == version)
}

#[must_use]
pub(crate) fn builtin_methods(version: u32) -> Option<&'static [&'static str]> {
    builtin_table(version).map(|table: &BuiltinTable| table.methods)
}

#[must_use]
pub fn get_template_object_builtin(version: u32) -> Option<u64> {
    builtin_table(version).map(|table: &BuiltinTable| table.template_object_id)
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

        let v62: &[&str] = builtin_methods(62).expect("hbc v62 builtin table");
        let v71: &[&str] = builtin_methods(71).expect("hbc v71 builtin table");
        let v74: &[&str] = builtin_methods(74).expect("hbc v74 builtin table");
        let v83: &[&str] = builtin_methods(83).expect("hbc v83 builtin table");
        let v89: &[&str] = builtin_methods(89).expect("hbc v89 builtin table");
        assert_eq!(
            v62.len(),
            49,
            "include/hermes/Inst/Builtins.def at facebook/hermes tag v0.2.1 expands to 49 \
             BUILTIN_METHOD entries, because the HermesInternal helpers are public builtins at that \
             release rather than the private list they become later"
        );
        assert_eq!(
            v71.len(),
            53,
            "tag v0.3.0 adds throwTypeError, generatorSetDelegated, arraySpread and apply to the \
             HermesInternal block, which renumbers every builtin after ensureObject"
        );
        assert_ne!(
            v62, v71,
            "hbc v62 and v71 share an opcode table but not a builtin table, so one list for both \
             would name the wrong method for every id past ensureObject"
        );
        assert_eq!(v74, v76, "hbc v74 and v76 share one builtin numbering");
        assert_eq!(v83, v84, "hbc v83 and v84 share one builtin numbering");
        assert_eq!(
            v89.len(),
            37,
            "tag v0.12.0 already drops ArrayBuffer.isView, Date.now and Math.random"
        );
        assert_eq!(v89, v96, "hbc v89 and v96 share one builtin numbering");
        assert_eq!(
            builtin_name(62, 10),
            "HermesInternal.copyDataProperties",
            "id 10 is copyDataProperties at hbc v62 and throwTypeError at v71, so one shared table \
             would print a call the bundle never made"
        );
        assert_eq!(builtin_name(71, 10), "HermesInternal.throwTypeError");

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

    const GET_TEMPLATE_OBJECT_PRIVATE_INDEX: u64 = 2;
    const PUBLIC_TEMPLATE_OBJECT_METHOD: &str = "HermesInternal.getTemplateObject";

    #[test]
    fn the_template_object_builtin_carries_the_id_its_own_release_gives_it() {
        assert_eq!(get_template_object_builtin(96), Some(39));
        assert_eq!(get_template_object_builtin(89), Some(39));
        assert_eq!(get_template_object_builtin(84), Some(42));
        assert_eq!(get_template_object_builtin(83), Some(42));
        assert_eq!(get_template_object_builtin(76), Some(42));
        assert_eq!(get_template_object_builtin(74), Some(42));
        assert_eq!(get_template_object_builtin(71), Some(8));
        assert_eq!(get_template_object_builtin(62), Some(8));

        let mut public_releases: usize = 0;
        let mut private_releases: usize = 0;
        for table in BUILTIN_TABLES {
            let version: u32 = table.version;
            let id: u64 = get_template_object_builtin(version)
                .unwrap_or_else(|| panic!("hbc v{version} states its template-object builtin id"));
            assert!(is_template_object_builtin(version, id), "hbc v{version}");
            match table
                .methods
                .iter()
                .position(|name: &&str| *name == PUBLIC_TEMPLATE_OBJECT_METHOD)
            {
                Some(at) => {
                    assert_eq!(
                        u64::try_from(at).ok(),
                        Some(id),
                        "getTemplateObject is a public BUILTIN_METHOD at {}, so its id is its index \
                         in that list rather than an offset past the end of it",
                        table.upstream_tag
                    );
                    assert_eq!(
                        builtin_name(version, id),
                        PUBLIC_TEMPLATE_OBJECT_METHOD,
                        "hbc v{version} names this builtin in its own method table, so printing the \
                         private spelling would hide which method the bundle called"
                    );
                    public_releases += 1;
                }
                None => {
                    assert_eq!(
                        u64::try_from(table.methods.len())
                            .ok()
                            .map(|count: u64| count + GET_TEMPLATE_OBJECT_PRIVATE_INDEX),
                        Some(id),
                        "getTemplateObject is the third PRIVATE_BUILTIN at {}, and the private list \
                         is numbered after the public one",
                        table.upstream_tag
                    );
                    assert_eq!(builtin_name(version, id), "$getTemplateObject");
                    private_releases += 1;
                }
            }
        }
        assert_eq!(
            (public_releases, private_releases),
            (2, 6),
            "hbc v62 and v71 reach getTemplateObject as a public builtin and the six later graded \
             releases reach it as a private one; a split of any other shape means a table was \
             copied from the wrong release"
        );

        assert!(
            !is_template_object_builtin(76, 39),
            "id 39 is String.fromCharCode at hbc v76, so reading it as the template-object builtin \
             would rewrite an ordinary call into a template literal"
        );
        assert!(
            !is_template_object_builtin(96, 42),
            "id 42 is not the template-object builtin at hbc v96"
        );
        assert!(
            !is_template_object_builtin(62, 42),
            "id 42 is past the end of the hbc v62 method table and is not its template-object \
             builtin either"
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
        for absent in [0u32, 60, 61, 63, 70, 75, 82, 90, 95, u32::MAX] {
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
