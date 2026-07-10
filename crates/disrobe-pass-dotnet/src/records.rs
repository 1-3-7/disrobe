use crate::model::{MethodModel, TypeModel};

const VALUE_TYPE_BASE: &str = "System.ValueType";

fn short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

#[must_use]
pub fn is_record_type(ty: &TypeModel) -> bool {
    is_record_class(ty) || is_record_struct(ty)
}

fn is_record_class(ty: &TypeModel) -> bool {
    ty.methods
        .iter()
        .any(|m: &MethodModel| short_name(&m.name) == "get_EqualityContract")
}

#[must_use]
pub fn is_record_struct(ty: &TypeModel) -> bool {
    if ty.base_type.as_deref() != Some(VALUE_TYPE_BASE) {
        return false;
    }
    let names: Vec<&str> = ty
        .methods
        .iter()
        .map(|m: &MethodModel| short_name(&m.name))
        .collect();
    names.contains(&"PrintMembers")
        && names.contains(&"Deconstruct")
        && names.contains(&"op_Equality")
        && names.contains(&"op_Inequality")
}

#[must_use]
pub fn is_synthesized_record_member(m: &MethodModel) -> bool {
    let short: &str = short_name(&m.name);
    matches!(
        short,
        "get_EqualityContract"
            | "Equals"
            | "GetHashCode"
            | "op_Equality"
            | "op_Inequality"
            | "PrintMembers"
            | "Deconstruct"
            | "ToString"
    ) || short == "<Clone>$"
        || short.ends_with(">$")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::signature::MethodSig;

    fn method(name: &str) -> MethodModel {
        MethodModel {
            token: 0,
            name: name.to_owned(),
            flags: 0,
            impl_flags: 0,
            rva: 1,
            signature: MethodSig::default(),
            parameters: Vec::new(),
        }
    }

    fn ty(name: &str, methods: Vec<MethodModel>) -> TypeModel {
        TypeModel {
            token: 0x0200_0001,
            namespace: String::new(),
            name: name.to_owned(),
            full_name: name.to_owned(),
            flags: 0,
            base_type: None,
            fields: Vec::new(),
            methods,
        }
    }

    fn value_ty(name: &str, methods: Vec<MethodModel>) -> TypeModel {
        TypeModel {
            base_type: Some("System.ValueType".to_owned()),
            ..ty(name, methods)
        }
    }

    #[test]
    fn detects_record_via_equality_contract() {
        let t: TypeModel = ty(
            "User",
            vec![method("get_EqualityContract"), method("Deconstruct")],
        );
        assert!(is_record_type(&t));
    }

    #[test]
    fn plain_class_is_not_a_record() {
        let t: TypeModel = ty("Service", vec![method("DoWork"), method("ToString")]);
        assert!(!is_record_type(&t));
    }

    #[test]
    fn detects_record_struct_without_equality_contract() {
        let t: TypeModel = value_ty(
            "Coordinate",
            vec![
                method("PrintMembers"),
                method("Deconstruct"),
                method("op_Equality"),
                method("op_Inequality"),
                method("GetHashCode"),
                method("ToString"),
            ],
        );
        assert!(is_record_struct(&t));
        assert!(is_record_type(&t));
    }

    #[test]
    fn plain_struct_is_not_a_record_struct() {
        let t: TypeModel = value_ty("Rgb", vec![method("get_Red"), method("ToString")]);
        assert!(!is_record_struct(&t));
        assert!(!is_record_type(&t));
    }

    #[test]
    fn record_shaped_methods_on_a_reference_type_are_not_a_record_struct() {
        let t: TypeModel = ty(
            "Fake",
            vec![
                method("PrintMembers"),
                method("Deconstruct"),
                method("op_Equality"),
                method("op_Inequality"),
            ],
        );
        assert!(
            !is_record_struct(&t),
            "a reference type (no System.ValueType base) must never classify as a record struct"
        );
    }

    #[test]
    fn value_type_missing_a_record_member_is_not_a_record_struct() {
        let t: TypeModel = value_ty(
            "Rgb",
            vec![
                method("PrintMembers"),
                method("op_Equality"),
                method("op_Inequality"),
            ],
        );
        assert!(!is_record_struct(&t), "Deconstruct is missing");
    }

    #[test]
    fn classifies_synthesized_members() {
        assert!(is_synthesized_record_member(&method(
            "get_EqualityContract"
        )));
        assert!(is_synthesized_record_member(&method("<Clone>$")));
        assert!(is_synthesized_record_member(&method("Deconstruct")));
        assert!(is_synthesized_record_member(&method("op_Equality")));
        assert!(!is_synthesized_record_member(&method("CustomMethod")));
    }
}
