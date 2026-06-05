use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JavaType {
    Byte,
    Char,
    Double,
    Float,
    Int,
    Long,
    Short,
    Boolean,
    Void,
    Object(String),
    Array(Box<Self>),
}

impl JavaType {
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Byte => "byte".to_string(),
            Self::Char => "char".to_string(),
            Self::Double => "double".to_string(),
            Self::Float => "float".to_string(),
            Self::Int => "int".to_string(),
            Self::Long => "long".to_string(),
            Self::Short => "short".to_string(),
            Self::Boolean => "boolean".to_string(),
            Self::Void => "void".to_string(),
            Self::Object(internal) => binary_name_to_source(internal),
            Self::Array(inner) => format!("{}[]", inner.render()),
        }
    }

    #[inline]
    #[must_use]
    pub const fn category_two(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

#[must_use]
pub fn binary_to_source(internal: &str) -> String {
    if internal.starts_with('[')
        && let Some(ty) = parse_field(internal)
    {
        return ty.render();
    }
    binary_name_to_source(internal)
}

fn binary_name_to_source(internal: &str) -> String {
    let trimmed: &str = internal.trim_start_matches('L').trim_end_matches(';');
    let slashed: String = trimmed.replace('/', ".");
    let dotted: String = nested_separator_to_dot(&slashed);
    match dotted.strip_prefix("java.lang.") {
        Some(simple) if !simple.contains('.') => simple.to_string(),
        _ => dotted,
    }
}

/// Converts the JVM nested-class separator `$` to `.` only for named inner classes.
fn nested_separator_to_dot(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len());
    for (i, segment) in name.split('$').enumerate() {
        if i > 0 {
            let named: bool = segment
                .chars()
                .next()
                .is_some_and(|c: char| c.is_alphabetic() || c == '_');
            out.push(if named { '.' } else { '$' });
        }
        out.push_str(segment);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDescriptor {
    pub params: Vec<JavaType>,
    pub returns: JavaType,
}

pub const MAX_ARRAY_DIMENSIONS: u8 = 255;

#[must_use]
pub fn parse_field(descriptor: &str) -> Option<JavaType> {
    let bytes: &[u8] = descriptor.as_bytes();
    let (ty, consumed): (JavaType, usize) = parse_one(bytes, 0)?;
    if consumed == bytes.len() {
        Some(ty)
    } else {
        None
    }
}

#[must_use]
pub fn parse_method(descriptor: &str) -> Option<MethodDescriptor> {
    let bytes: &[u8] = descriptor.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut pos: usize = 1;
    let mut params: Vec<JavaType> = Vec::new();
    while pos < bytes.len() && bytes[pos] != b')' {
        let (ty, consumed): (JavaType, usize) = parse_one(bytes, pos)?;
        params.push(ty);
        pos = consumed;
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return None;
    }
    pos += 1;
    let (returns, consumed): (JavaType, usize) = parse_one(bytes, pos)?;
    if consumed == bytes.len() {
        Some(MethodDescriptor { params, returns })
    } else {
        None
    }
}

fn parse_one(bytes: &[u8], start: usize) -> Option<(JavaType, usize)> {
    let mut dims: usize = 0;
    let mut pos: usize = start;
    while bytes.get(pos) == Some(&b'[') {
        dims += 1;
        if dims > MAX_ARRAY_DIMENSIONS as usize {
            return None;
        }
        pos += 1;
    }
    let first: u8 = *bytes.get(pos)?;
    let (base, consumed): (JavaType, usize) = match first {
        b'B' => (JavaType::Byte, pos + 1),
        b'C' => (JavaType::Char, pos + 1),
        b'D' => (JavaType::Double, pos + 1),
        b'F' => (JavaType::Float, pos + 1),
        b'I' => (JavaType::Int, pos + 1),
        b'J' => (JavaType::Long, pos + 1),
        b'S' => (JavaType::Short, pos + 1),
        b'Z' => (JavaType::Boolean, pos + 1),
        b'V' => (JavaType::Void, pos + 1),
        b'L' => {
            let mut end: usize = pos + 1;
            while end < bytes.len() && bytes[end] != b';' {
                end += 1;
            }
            if end >= bytes.len() {
                return None;
            }
            let name: String = String::from_utf8_lossy(&bytes[pos..=end]).into_owned();
            (JavaType::Object(name), end + 1)
        }
        _ => return None,
    };
    let mut ty: JavaType = base;
    for _ in 0..dims {
        ty = JavaType::Array(Box::new(ty));
    }
    Some((ty, consumed))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_primitive_field() {
        assert_eq!(parse_field("I"), Some(JavaType::Int));
        assert_eq!(parse_field("Z"), Some(JavaType::Boolean));
    }

    #[test]
    fn parses_object_field() {
        assert_eq!(
            parse_field("Ljava/lang/String;"),
            Some(JavaType::Object("Ljava/lang/String;".to_string()))
        );
    }

    #[test]
    fn renders_java_lang_simply() {
        let t: JavaType = parse_field("Ljava/lang/String;").unwrap();
        assert_eq!(t.render(), "String");
    }

    #[test]
    fn renders_array_dimensions() {
        let t: JavaType = parse_field("[[I").unwrap();
        assert_eq!(t.render(), "int[][]");
    }

    #[test]
    fn parses_method_descriptor() {
        let m: MethodDescriptor = parse_method("(ILjava/lang/String;[B)V").unwrap();
        assert_eq!(m.params.len(), 3);
        assert_eq!(m.returns, JavaType::Void);
        assert_eq!(m.params[0], JavaType::Int);
        assert_eq!(m.params[2], JavaType::Array(Box::new(JavaType::Byte)));
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert_eq!(parse_field("IJ"), None);
    }

    #[test]
    fn renders_fully_qualified_non_java_lang() {
        let t: JavaType = parse_field("Lcom/example/Foo;").unwrap();
        assert_eq!(t.render(), "com.example.Foo");
    }
}
