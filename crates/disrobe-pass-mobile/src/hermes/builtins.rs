/// Native builtin method names, indexed by builtin id, from Hermes
/// `FrontEndDefs/Builtins.def` (`BUILTIN_METHOD(object, name)` declaration
/// order, ids 0..37). These are stable across the v60..96 range targeted here.
const NATIVE_BUILTINS: &[&str] = &[
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

/// Id of the `getTemplateObject` private builtin.
///
/// Native count plus the offset of `getTemplateObject` within the
/// `PRIVATE_BUILTIN` list (silentSetPrototypeOf, requireFast, getTemplateObject).
/// It tags tagged-template construction, the signal the template-literal
/// detector keys on.
pub const BUILTIN_GET_TEMPLATE_OBJECT: u64 = NATIVE_BUILTINS.len() as u64 + 2;

/// Resolves a `CallBuiltin` builtin id to its JS name.
///
/// Native methods resolve to `Object.method`; the private template-object
/// builtin resolves to a readable marker; ids past the known native range
/// resolve to `$builtin{N}` honestly rather than guessing a private/JS-builtin
/// name whose numbering shifts between bytecode versions.
#[must_use]
pub fn builtin_name(id: u64) -> String {
    if let Some(name) = NATIVE_BUILTINS.get(id as usize) {
        return (*name).to_owned();
    }
    if id == BUILTIN_GET_TEMPLATE_OBJECT {
        return "$getTemplateObject".to_owned();
    }
    format!("$builtin{id}")
}

/// Whether a `CallBuiltin` id denotes tagged-template-object construction, the
/// detector hook for reconstructing template literals.
#[must_use]
pub const fn is_template_object_builtin(id: u64) -> bool {
    id == BUILTIN_GET_TEMPLATE_OBJECT
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn native_builtins_resolve() {
        assert_eq!(builtin_name(0), "Array.isArray");
        assert_eq!(builtin_name(3), "JSON.parse");
        assert_eq!(builtin_name(34), "Object.keys");
        assert_eq!(builtin_name(36), "String.fromCharCode");
    }

    #[test]
    fn template_object_builtin_is_tagged() {
        assert_eq!(BUILTIN_GET_TEMPLATE_OBJECT, 39);
        assert!(is_template_object_builtin(BUILTIN_GET_TEMPLATE_OBJECT));
        assert_eq!(
            builtin_name(BUILTIN_GET_TEMPLATE_OBJECT),
            "$getTemplateObject"
        );
    }

    #[test]
    fn unknown_builtin_is_honest_placeholder() {
        assert_eq!(builtin_name(200), "$builtin200");
        assert!(!is_template_object_builtin(200));
    }
}
