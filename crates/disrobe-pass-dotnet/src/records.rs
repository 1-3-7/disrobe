use crate::model::{MethodModel, TypeModel};

fn short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

#[must_use]
pub fn is_record_type(ty: &TypeModel) -> bool {
    ty.methods
        .iter()
        .any(|m: &MethodModel| short_name(&m.name) == "get_EqualityContract")
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
