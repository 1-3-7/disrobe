use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::macho::{self, ParsedSlice, Section, SliceView};

const FIELD_DESCRIPTOR_HEADER: usize = 16;
const FIELD_RECORD_SIZE: usize = 12;
const MAX_FIELDS_PER_TYPE: usize = 1 << 16;
const MAX_DESCRIPTORS: usize = 1 << 18;
const MAX_CSTR: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldDescriptorKind {
    Struct,
    Class,
    Enum,
    MultiPayloadEnum,
    Protocol,
    ClassProtocol,
    ObjcProtocol,
    ObjcClass,
    Unknown(u16),
}

impl FieldDescriptorKind {
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            0 => Self::Struct,
            1 => Self::Class,
            2 => Self::Enum,
            3 => Self::MultiPayloadEnum,
            4 => Self::Protocol,
            5 => Self::ClassProtocol,
            6 => Self::ObjcProtocol,
            7 => Self::ObjcClass,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Class | Self::ObjcClass => "class",
            Self::Enum | Self::MultiPayloadEnum => "enum",
            Self::Protocol | Self::ClassProtocol | Self::ObjcProtocol => "protocol",
            Self::Unknown(_) => "type",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftField {
    pub name: String,
    pub mangled_type: Option<String>,
    pub demangled_type: Option<String>,
    pub is_indirect_enum_case: bool,
    pub is_var: bool,
}

impl SwiftField {
    #[must_use]
    pub fn display_type(&self) -> String {
        if let Some(d) = self.demangled_type.as_deref() {
            return d.to_owned();
        }
        match self.mangled_type.as_deref() {
            Some(m) if m.bytes().any(|b: u8| b < 0x20) => "<symbolic-ref>".to_owned(),
            Some(m) => m.to_owned(),
            None => "_".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftTypeReflection {
    pub mangled_type_name: Option<String>,
    pub demangled_type_name: Option<String>,
    pub superclass: Option<String>,
    pub kind: FieldDescriptorKind,
    pub fields: Vec<SwiftField>,
}

impl SwiftTypeReflection {
    #[must_use]
    pub fn render(&self) -> String {
        let kw: &str = self.kind.keyword();
        let display: &str = self
            .demangled_type_name
            .as_deref()
            .or(self.mangled_type_name.as_deref())
            .unwrap_or("<anonymous>");
        let mut out: String = String::new();
        match &self.superclass {
            Some(sup) => {
                let _ = writeln!(out, "{kw} {display} : {sup} {{");
            }
            None => {
                let _ = writeln!(out, "{kw} {display} {{");
            }
        }
        for field in &self.fields {
            let decl: &str = if field.is_var { "var" } else { "let" };
            let ty: String = field.display_type();
            let _ = writeln!(out, "    {decl} {}: {ty}", field.name);
        }
        out.push_str("}\n");
        out
    }
}

fn read_field_record(
    view: &SliceView<'_>,
    rec_off: usize,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Option<SwiftField> {
    let flags: u32 = view.read_u32_at(rec_off)?;
    let mangled_type: Option<String> =
        rel_string(view, rec_off + 4).filter(|s: &String| !s.is_empty());
    let name: String = rel_string(view, rec_off + 8)?;
    let demangled_type: Option<String> = mangled_type
        .as_deref()
        .and_then(|m: &str| demangle(m).filter(|d: &String| d != m));
    Some(SwiftField {
        name,
        demangled_type,
        mangled_type,
        is_indirect_enum_case: flags & 0x1 != 0,
        is_var: flags & 0x2 != 0,
    })
}

fn rel_string(view: &SliceView<'_>, field_off: usize) -> Option<String> {
    let rel: i32 = view.read_u32_at(field_off)? as i32;
    if rel == 0 {
        return None;
    }
    let target: i64 = i64::try_from(field_off).ok()? + i64::from(rel);
    let target_off: usize = usize::try_from(target).ok()?;
    view.cstr_at_offset(target_off, MAX_CSTR)
}

#[must_use]
pub fn parse_field_descriptors(
    slice: &[u8],
    parsed: &ParsedSlice,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Vec<SwiftTypeReflection> {
    let Some(section): Option<&Section> = macho::find_section(parsed, "__TEXT", "__swift5_fieldmd")
    else {
        return Vec::new();
    };
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return Vec::new();
    };
    let sect_start: usize = section.offset as usize;
    let Ok(sect_len): core::result::Result<usize, _> = usize::try_from(section.size) else {
        return Vec::new();
    };
    let Some(sect_end): Option<usize> = sect_start.checked_add(sect_len) else {
        return Vec::new();
    };
    if sect_end > slice.len() {
        return Vec::new();
    }

    let mut out: Vec<SwiftTypeReflection> = Vec::new();
    let mut cursor: usize = sect_start;
    let mut guard: usize = 0;
    while cursor + FIELD_DESCRIPTOR_HEADER <= sect_end && guard < MAX_DESCRIPTORS {
        guard += 1;
        let Some(kind_raw): Option<u32> = view.read_u32_at(cursor + 8) else {
            break;
        };
        let kind: FieldDescriptorKind = FieldDescriptorKind::from_raw((kind_raw & 0xFFFF) as u16);
        let record_size: u16 = ((kind_raw >> 16) & 0xFFFF) as u16;
        let Some(num_fields): Option<u32> = view.read_u32_at(cursor + 12) else {
            break;
        };
        let num_fields_usize: usize = num_fields as usize;
        let elem_size: usize = if record_size == 0 {
            FIELD_RECORD_SIZE
        } else {
            record_size as usize
        };
        if num_fields_usize > MAX_FIELDS_PER_TYPE {
            break;
        }
        let records_bytes: usize = num_fields_usize.saturating_mul(elem_size);
        let descriptor_end: usize = cursor + FIELD_DESCRIPTOR_HEADER + records_bytes;
        if descriptor_end > sect_end {
            break;
        }

        let mangled_type_name: Option<String> =
            rel_string(&view, cursor).filter(|s: &String| !s.is_empty());
        let superclass: Option<String> =
            rel_string(&view, cursor + 4).filter(|s: &String| !s.is_empty());
        let demangled_type_name: Option<String> = mangled_type_name
            .as_deref()
            .and_then(|m: &str| demangle(m).filter(|d: &String| d != m));

        let mut fields: Vec<SwiftField> = Vec::with_capacity(num_fields_usize);
        for i in 0..num_fields_usize {
            let rec_off: usize = cursor + FIELD_DESCRIPTOR_HEADER + i * elem_size;
            if let Some(field) = read_field_record(&view, rec_off, demangle) {
                fields.push(field);
            }
        }

        if mangled_type_name.is_some() || !fields.is_empty() {
            out.push(SwiftTypeReflection {
                mangled_type_name,
                demangled_type_name,
                superclass,
                kind,
                fields,
            });
        }
        cursor = descriptor_end;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_raw_maps_known_values() {
        assert_eq!(
            FieldDescriptorKind::from_raw(0),
            FieldDescriptorKind::Struct
        );
        assert_eq!(FieldDescriptorKind::from_raw(1), FieldDescriptorKind::Class);
        assert_eq!(FieldDescriptorKind::from_raw(2), FieldDescriptorKind::Enum);
        assert_eq!(
            FieldDescriptorKind::from_raw(99),
            FieldDescriptorKind::Unknown(99)
        );
    }

    #[test]
    fn render_emits_struct_with_fields() {
        let refl: SwiftTypeReflection = SwiftTypeReflection {
            mangled_type_name: Some("$s3App4UserV".to_owned()),
            demangled_type_name: Some("App.User".to_owned()),
            superclass: None,
            kind: FieldDescriptorKind::Struct,
            fields: vec![SwiftField {
                name: "id".to_owned(),
                mangled_type: Some("Si".to_owned()),
                demangled_type: Some("Swift.Int".to_owned()),
                is_indirect_enum_case: false,
                is_var: true,
            }],
        };
        let rendered: String = refl.render();
        assert!(rendered.starts_with("struct App.User {"));
        assert!(rendered.contains("var id: Swift.Int"));
    }
}
