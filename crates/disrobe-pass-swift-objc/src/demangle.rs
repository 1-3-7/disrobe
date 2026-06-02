use crate::error::{Error, Result};

const MAX_DEPTH: usize = 256;

#[must_use]
pub fn looks_like_swift_mangled(s: &str) -> bool {
    s.starts_with("_$s")
        || s.starts_with("$s")
        || s.starts_with("_$S")
        || s.starts_with("$S")
        || s.starts_with("_T0")
        || s.starts_with("_T")
}

pub fn demangle(symbol: &str) -> Result<String> {
    let trimmed: &str = symbol.strip_prefix('_').unwrap_or(symbol);
    let body: &str = trimmed
        .strip_prefix("$s")
        .or_else(|| trimmed.strip_prefix("$S"))
        .or_else(|| trimmed.strip_prefix("T0"))
        .ok_or_else(|| Error::Demangle(symbol.to_owned()))?;
    let mut parser: Parser<'_> = Parser::new(body);
    let nodes: Vec<Node> = parser
        .parse_top_level()
        .map_err(|()| Error::Demangle(symbol.to_owned()))?;
    if nodes.is_empty() {
        return Err(Error::Demangle(symbol.to_owned()));
    }
    Ok(render_top_level(&nodes))
}

#[must_use]
pub fn contains_symbolic_reference(mangled: &str) -> bool {
    mangled.bytes().any(|b: u8| b < 0x20)
}

#[must_use]
pub fn demangle_type(mangled: &str) -> Option<String> {
    if mangled.is_empty() || contains_symbolic_reference(mangled) {
        return None;
    }
    let mut parser: Parser<'_> = Parser::new(mangled);
    let node: Node = parser.parse_type_stack().ok()??;
    let rendered: String = render_node(&node);
    if rendered.is_empty()
        || rendered == mangled
        || rendered.contains("<symbolic>")
        || rendered.bytes().any(|b: u8| b < 0x20)
    {
        None
    } else {
        Some(rendered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Nominal {
        kind: NominalKind,
        path: Vec<String>,
    },
    BoundGeneric {
        base: Box<Self>,
        args: Vec<Self>,
    },
    Optional(Box<Self>),
    Array(Box<Self>),
    Dictionary(Box<Self>, Box<Self>),
    Tuple(Vec<(Option<String>, Self)>),
    Metatype(Box<Self>),
    SymbolicRef,
    GenericParam(u32, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NominalKind {
    Class,
    Struct,
    Enum,
    Protocol,
    TypeAlias,
    Other,
}

impl NominalKind {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Class => " (class)",
            Self::Struct => " (struct)",
            Self::Enum => " (enum)",
            Self::Protocol => " (protocol)",
            Self::TypeAlias | Self::Other => "",
        }
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            src: s.as_bytes(),
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b: Option<u8> = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn parse_top_level(&mut self) -> core::result::Result<Vec<Node>, ()> {
        let mut path: Vec<String> = Vec::new();
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                let ident: String = self.parse_identifier()?;
                path.push(ident);
            } else {
                break;
            }
        }
        if path.is_empty() {
            return Err(());
        }
        let kind: NominalKind = self.nominal_kind_from_suffix();
        Ok(vec![Node::Nominal { kind, path }])
    }

    fn nominal_kind_from_suffix(&mut self) -> NominalKind {
        match self.peek() {
            Some(b'C') => {
                self.pos += 1;
                NominalKind::Class
            }
            Some(b'V') => {
                self.pos += 1;
                NominalKind::Struct
            }
            Some(b'O') => {
                self.pos += 1;
                NominalKind::Enum
            }
            Some(b'P') => {
                self.pos += 1;
                NominalKind::Protocol
            }
            Some(b'a') => {
                self.pos += 1;
                NominalKind::TypeAlias
            }
            _ => NominalKind::Other,
        }
    }

    fn parse_identifier(&mut self) -> core::result::Result<String, ()> {
        let mut len: usize = 0;
        let mut saw_digit: bool = false;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                saw_digit = true;
                let digit: usize = (b - b'0') as usize;
                len = len
                    .checked_mul(10)
                    .and_then(|v: usize| v.checked_add(digit))
                    .ok_or(())?;
                self.pos += 1;
            } else {
                break;
            }
        }
        if !saw_digit || len == 0 {
            return Err(());
        }
        let end: usize = self.pos.checked_add(len).ok_or(())?;
        let raw: &[u8] = self.src.get(self.pos..end).ok_or(())?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        self.pos = end;
        Ok(s)
    }

    fn parse_nominal_path(&mut self) -> core::result::Result<Node, ()> {
        let mut path: Vec<String> = Vec::new();
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                path.push(self.parse_identifier()?);
            } else {
                break;
            }
        }
        if path.is_empty() {
            return Err(());
        }
        let kind: NominalKind = self.nominal_kind_from_suffix();
        Ok(Node::Nominal { kind, path })
    }

    fn parse_type_stack(&mut self) -> core::result::Result<Option<Node>, ()> {
        let mut stack: Vec<Node> = Vec::new();
        while let Some(b) = self.peek() {
            if self.depth >= MAX_DEPTH {
                return Err(());
            }
            if b == 0x01 || b == 0x02 {
                self.consume_symbolic_ref();
                stack.push(Node::SymbolicRef);
                continue;
            }
            if b.is_ascii_digit() {
                stack.push(self.parse_nominal_path()?);
                continue;
            }
            match b {
                b'S' => {
                    self.pos += 1;
                    self.apply_standard_substitution(&mut stack);
                }
                b'y' | b'G' => {
                    self.pos += 1;
                    self.apply_bound_generic(&mut stack);
                }
                b'x' => {
                    self.pos += 1;
                    stack.push(Node::GenericParam(0, 0));
                }
                b'q' => {
                    self.pos += 1;
                    let idx: u32 = self.parse_index();
                    stack.push(Node::GenericParam(0, idx));
                }
                b't' => {
                    self.pos += 1;
                    let tuple: Node = build_tuple(&mut stack);
                    stack.push(tuple);
                }
                b'm' => {
                    self.pos += 1;
                    if let Some(inner) = stack.pop() {
                        stack.push(Node::Metatype(Box::new(inner)));
                    }
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
        Ok(stack.pop())
    }

    fn apply_standard_substitution(&mut self, stack: &mut Vec<Node>) {
        let Some(c): Option<u8> = self.bump() else {
            return;
        };
        let nominal = |name: &str| Node::Nominal {
            kind: NominalKind::Struct,
            path: vec!["Swift".to_owned(), name.to_owned()],
        };
        match c {
            b'i' => stack.push(nominal("Int")),
            b'u' => stack.push(nominal("UInt")),
            b'f' => stack.push(nominal("Float")),
            b'd' => stack.push(nominal("Double")),
            b'b' => stack.push(nominal("Bool")),
            b'S' => stack.push(nominal("String")),
            b's' => stack.push(nominal("Substring")),
            b'c' => stack.push(nominal("UnicodeScalar")),
            b'J' => stack.push(nominal("Character")),
            b'V' => stack.push(nominal("UnsafeRawPointer")),
            b'p' => stack.push(Node::Nominal {
                kind: NominalKind::Other,
                path: vec!["Swift".to_owned(), "AnyObject".to_owned()],
            }),
            b'a' => stack.push(Node::Nominal {
                kind: NominalKind::Struct,
                path: vec!["Swift".to_owned(), "Array".to_owned()],
            }),
            b'D' => stack.push(Node::Nominal {
                kind: NominalKind::Struct,
                path: vec!["Swift".to_owned(), "Dictionary".to_owned()],
            }),
            b'g' | b'q' => {
                let inner: Node = stack.pop().unwrap_or(Node::SymbolicRef);
                stack.push(Node::Optional(Box::new(inner)));
            }
            _ => stack.push(nominal("Any")),
        }
    }

    fn apply_bound_generic(&mut self, stack: &mut Vec<Node>) {
        self.depth += 1;
        let mut args: Vec<Node> = Vec::new();
        while let Some(b) = self.peek() {
            if b == b'G' {
                self.pos += 1;
                break;
            }
            if b == 0x01 || b == 0x02 {
                self.consume_symbolic_ref();
                args.push(Node::SymbolicRef);
                continue;
            }
            if b.is_ascii_digit() {
                let Ok(node): core::result::Result<Node, ()> = self.parse_nominal_path() else {
                    break;
                };
                args.push(node);
                continue;
            }
            match b {
                b'S' => {
                    self.pos += 1;
                    self.apply_standard_substitution(&mut args);
                }
                b'y' => {
                    self.pos += 1;
                    self.apply_bound_generic(&mut args);
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
        self.depth -= 1;
        let base: Option<Node> = stack.pop();
        match base {
            Some(Node::Nominal { path, .. }) if path == ["Swift", "Array"] => {
                let arg: Node = args.into_iter().next().unwrap_or(Node::SymbolicRef);
                stack.push(Node::Array(Box::new(arg)));
            }
            Some(Node::Nominal { path, .. }) if path == ["Swift", "Dictionary"] => {
                let mut it: std::vec::IntoIter<Node> = args.into_iter();
                let k: Node = it.next().unwrap_or(Node::SymbolicRef);
                let v: Node = it.next().unwrap_or(Node::SymbolicRef);
                stack.push(Node::Dictionary(Box::new(k), Box::new(v)));
            }
            Some(b) => stack.push(Node::BoundGeneric {
                base: Box::new(b),
                args,
            }),
            None => {}
        }
    }

    fn consume_symbolic_ref(&mut self) {
        let kind: Option<u8> = self.bump();
        let width: usize = match kind {
            Some(0x01 | 0x02) => 4,
            Some(0x03..=0x09) => 8,
            _ => 0,
        };
        for _ in 0..width {
            if self.bump().is_none() {
                break;
            }
        }
        if matches!(self.peek(), Some(0x02)) {
            self.pos += 1;
        }
    }

    fn parse_index(&mut self) -> u32 {
        let mut value: u32 = 0;
        let mut saw: bool = false;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                saw = true;
                value = value.saturating_mul(10).saturating_add(u32::from(b - b'0'));
                self.pos += 1;
            } else {
                break;
            }
        }
        if matches!(self.peek(), Some(b'_')) {
            self.pos += 1;
        }
        if saw { value + 1 } else { 0 }
    }
}

fn build_tuple(stack: &mut Vec<Node>) -> Node {
    let elems: Vec<(Option<String>, Node)> = stack.drain(..).map(|n: Node| (None, n)).collect();
    Node::Tuple(elems)
}

fn render_top_level(nodes: &[Node]) -> String {
    nodes.iter().map(render_node_with_suffix).collect()
}

fn render_node_with_suffix(node: &Node) -> String {
    match node {
        Node::Nominal { kind, path } => format!("{}{}", path.join("."), kind.suffix()),
        other => render_node(other),
    }
}

fn render_node(node: &Node) -> String {
    match node {
        Node::Nominal { path, .. } => path.join("."),
        Node::BoundGeneric { base, args } => {
            let rendered_args: String = args
                .iter()
                .map(render_node)
                .collect::<Vec<String>>()
                .join(", ");
            format!("{}<{rendered_args}>", render_node(base))
        }
        Node::Optional(inner) => format!("{}?", render_node(inner)),
        Node::Array(inner) => format!("[{}]", render_node(inner)),
        Node::Dictionary(k, v) => format!("[{}: {}]", render_node(k), render_node(v)),
        Node::Tuple(elems) => {
            let rendered: String = elems
                .iter()
                .map(|(label, ty): &(Option<String>, Node)| {
                    label.as_ref().map_or_else(
                        || render_node(ty),
                        |l: &String| format!("{l}: {}", render_node(ty)),
                    )
                })
                .collect::<Vec<String>>()
                .join(", ");
            format!("({rendered})")
        }
        Node::Metatype(inner) => format!("{}.Type", render_node(inner)),
        Node::SymbolicRef => "<symbolic>".to_owned(),
        Node::GenericParam(depth, idx) => format!("τ_{depth}_{idx}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn demangle_simple_class() {
        assert_eq!(
            demangle("$s5Hello5WorldC").expect("d"),
            "Hello.World (class)"
        );
    }

    #[test]
    fn demangle_simple_struct() {
        assert_eq!(demangle("$s3App4UserV").expect("d"), "App.User (struct)");
    }

    #[test]
    fn demangle_three_component_path() {
        assert_eq!(
            demangle("$s11SwiftDriver10ProcessSetC").expect("d"),
            "SwiftDriver.ProcessSet (class)"
        );
    }

    #[test]
    fn demangle_rejects_non_swift() {
        assert!(demangle("foo").is_err());
    }

    #[test]
    fn demangle_type_standard_substitutions() {
        assert_eq!(demangle_type("Si").as_deref(), Some("Swift.Int"));
        assert_eq!(demangle_type("SS").as_deref(), Some("Swift.String"));
        assert_eq!(demangle_type("Su").as_deref(), Some("Swift.UInt"));
        assert_eq!(demangle_type("Sb").as_deref(), Some("Swift.Bool"));
        assert_eq!(demangle_type("Sd").as_deref(), Some("Swift.Double"));
    }

    #[test]
    fn demangle_type_array_of_string() {
        assert_eq!(demangle_type("SaySSG").as_deref(), Some("[Swift.String]"));
    }

    #[test]
    fn demangle_type_dictionary_sugar() {
        assert_eq!(
            demangle_type("SDySSSiG").as_deref(),
            Some("[Swift.String: Swift.Int]")
        );
    }

    #[test]
    fn demangle_type_optional_postfix() {
        assert_eq!(demangle_type("SSSg").as_deref(), Some("Swift.String?"));
    }

    #[test]
    fn demangle_type_nominal_path() {
        assert_eq!(
            demangle_type("11SwiftDriver10ProcessSetC").as_deref(),
            Some("SwiftDriver.ProcessSet")
        );
    }

    #[test]
    fn demangle_type_symbolic_ref_is_none_or_symbolic() {
        let symbolic: Vec<u8> = vec![0x01, 0x6b, 0xab, 0x00, 0x02];
        let s: String = String::from_utf8_lossy(&symbolic).into_owned();
        let out: Option<String> = demangle_type(&s);
        assert!(out.is_none() || out.as_deref() == Some("<symbolic>"));
    }
}
