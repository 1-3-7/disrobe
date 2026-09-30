use crate::decompile::{Literal, OpArray};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Protected,
    Private,
}

impl Visibility {
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Protected => "protected",
            Self::Private => "private",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Modifiers {
    pub visibility: Option<Visibility>,
    pub is_static: bool,
    pub is_abstract: bool,
    pub is_final: bool,
    pub is_readonly: bool,
}

impl Modifiers {
    #[must_use]
    pub fn render(self) -> String {
        let mut words: Vec<&'static str> = Vec::new();
        if self.is_abstract {
            words.push("abstract");
        }
        if self.is_final {
            words.push("final");
        }
        if let Some(visibility) = self.visibility {
            words.push(visibility.keyword());
        }
        if self.is_static {
            words.push("static");
        }
        if self.is_readonly {
            words.push("readonly");
        }
        words.join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub type_decl: Option<String>,
    pub by_reference: bool,
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub params: Vec<Parameter>,
    pub return_type: Option<String>,
    pub returns_reference: bool,
    pub modifiers: Modifiers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassKind {
    Class,
    Interface,
    Trait,
    Enum,
}

impl ClassKind {
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Trait => "trait",
            Self::Enum => "enum",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassConstant {
    pub name: String,
    pub modifiers: Modifiers,
    pub value: Literal,
    pub enum_case: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub modifiers: Modifiers,
    pub type_decl: Option<String>,
    pub default: Option<Literal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassDecl {
    pub name: String,
    pub declaration_key: String,
    pub kind: ClassKind,
    pub modifiers: Modifiers,
    pub enum_backing: Option<String>,
    pub parent: Option<String>,
    pub interfaces: Vec<String>,
    pub traits: Vec<String>,
    pub constants: Vec<ClassConstant>,
    pub properties: Vec<Property>,
    pub methods: Vec<OpArray>,
    pub unsupported: Option<String>,
}
