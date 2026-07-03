use crate::model::{FieldModel, MethodModel, TypeModel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateMachineKind {
    Async,

    Iterator,

    AsyncIterator,
}

#[derive(Debug, Clone)]
pub struct StateMachine {
    pub kind: StateMachineKind,

    pub type_token: u32,

    pub state_field: String,

    pub builder_field: Option<String>,

    pub current_field: Option<String>,
}

#[must_use]
pub fn is_state_field_name(name: &str) -> bool {
    let short: &str = short_name(name);
    short.contains("1__state") || short == "<>1__state" || short.ends_with("__state")
}

fn is_builder_field_name(name: &str) -> bool {
    let short: &str = short_name(name);
    short.contains("t__builder") || short.ends_with("__builder")
}

fn is_current_field_name(name: &str) -> bool {
    let short: &str = short_name(name);
    short.contains("2__current") || short.ends_with("__current")
}

fn short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

fn has_move_next(ty: &TypeModel) -> bool {
    ty.methods
        .iter()
        .any(|m: &MethodModel| short_name(&m.name) == "MoveNext")
}

fn field_named(ty: &TypeModel, pred: impl Fn(&str) -> bool) -> Option<&FieldModel> {
    ty.fields.iter().find(|f: &&FieldModel| pred(&f.name))
}

#[must_use]
pub fn classify(ty: &TypeModel) -> Option<StateMachine> {
    if !has_move_next(ty) {
        return None;
    }
    let state: &FieldModel = field_named(ty, is_state_field_name)?;
    let builder: Option<&FieldModel> = field_named(ty, is_builder_field_name);
    let current: Option<&FieldModel> = field_named(ty, is_current_field_name);

    let kind: StateMachineKind = match (builder.is_some(), current.is_some()) {
        (true, true) => StateMachineKind::AsyncIterator,
        (true, false) => StateMachineKind::Async,
        (false, _) => StateMachineKind::Iterator,
    };
    Some(StateMachine {
        kind,
        type_token: ty.token,
        state_field: short_name(&state.name).to_owned(),
        builder_field: builder.map(|f: &FieldModel| short_name(&f.name).to_owned()),
        current_field: current.map(|f: &FieldModel| short_name(&f.name).to_owned()),
    })
}

#[must_use]
pub fn is_move_next(m: &MethodModel) -> bool {
    short_name(&m.name) == "MoveNext"
}

#[must_use]
pub fn is_closure_display_type(ty: &TypeModel) -> bool {
    let short: &str = short_name(&ty.name);
    short == "<>c"
        || short.starts_with("<>c__DisplayClass")
        || short.starts_with("<>c_")
        || (short.starts_with("<>c") && short.len() > 3)
}

#[must_use]
pub fn is_hidden_state_machine_member(m: &MethodModel) -> bool {
    let short: &str = short_name(&m.name);
    matches!(
        short,
        "SetStateMachine" | "Reset" | "System.Collections.IEnumerator.Reset"
    ) || short.ends_with(".get_Current")
        || short.ends_with(".GetEnumerator")
        || short.ends_with(".Reset")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::signature::{MethodSig, TypeSig, TypeSigOrVoid};

    fn field(name: &str) -> FieldModel {
        FieldModel {
            token: 0,
            name: name.to_owned(),
            flags: 0,
            field_type: TypeSig::I4,
        }
    }

    fn method(name: &str) -> MethodModel {
        MethodModel {
            token: 0,
            name: name.to_owned(),
            flags: 0,
            impl_flags: 0,
            rva: 1,
            signature: MethodSig {
                has_this: true,
                return_type: TypeSigOrVoid::Void,
                ..MethodSig::default()
            },
            parameters: Vec::new(),
        }
    }

    fn ty(name: &str, fields: Vec<FieldModel>, methods: Vec<MethodModel>) -> TypeModel {
        TypeModel {
            token: 0x0200_0001,
            namespace: String::new(),
            name: name.to_owned(),
            full_name: name.to_owned(),
            flags: 0,
            base_type: None,
            fields,
            methods,
        }
    }

    #[test]
    fn detects_async_state_machine() {
        let t: TypeModel = ty(
            "<Foo>d__5",
            vec![field("<>1__state"), field("<>t__builder")],
            vec![method("MoveNext"), method("SetStateMachine")],
        );
        let sm: StateMachine = classify(&t).expect("async sm");
        assert_eq!(sm.kind, StateMachineKind::Async);
        assert_eq!(sm.state_field, "<>1__state");
        assert!(sm.builder_field.is_some());
    }

    #[test]
    fn detects_iterator_state_machine() {
        let t: TypeModel = ty(
            "<Bar>d__7",
            vec![field("<>1__state"), field("<>2__current")],
            vec![method("MoveNext"), method("System.IDisposable.Dispose")],
        );
        let sm: StateMachine = classify(&t).expect("iterator sm");
        assert_eq!(sm.kind, StateMachineKind::Iterator);
        assert!(sm.current_field.is_some());
        assert!(sm.builder_field.is_none());
    }

    #[test]
    fn detects_async_iterator_state_machine() {
        let t: TypeModel = ty(
            "<Baz>d__3",
            vec![
                field("<>1__state"),
                field("<>t__builder"),
                field("<>2__current"),
            ],
            vec![method("MoveNext")],
        );
        let sm: StateMachine = classify(&t).expect("async iterator sm");
        assert_eq!(sm.kind, StateMachineKind::AsyncIterator);
    }

    #[test]
    fn ordinary_type_is_not_a_state_machine() {
        let t: TypeModel = ty("User", vec![field("Id")], vec![method("ToString")]);
        assert!(classify(&t).is_none());
    }

    #[test]
    fn obfuscated_state_field_still_detected() {
        let t: TypeModel = ty(
            "x9281",
            vec![field("a__state"), field("z__builder")],
            vec![method("MoveNext")],
        );
        let sm: StateMachine = classify(&t).expect("renamed sm");
        assert_eq!(sm.kind, StateMachineKind::Async);
    }
}
