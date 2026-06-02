use disrobe_py_marshal::{CodeObject, Object};

const LOAD_GLOBAL_PRE_311: u8 = 116;
const LOAD_GLOBAL_311_PLUS: u8 = 112;
const CALL_FUNCTION: u8 = 131;
const SETUP_FINALLY: u8 = 122;
const END_FINALLY: u8 = 88;

#[cfg(test)]
const POP_TOP: u8 = 1;

pub(crate) fn has_wrap_header(co: &CodeObject) -> bool {
    let head: &Vec<u8> = &co.code;
    if head.len() < 8 {
        return false;
    }
    let names_have_armor: bool = co.names.iter().any(|n| {
        matches!(
            n,
            Object::ShortAscii { value, .. } | Object::String { value, .. }
                if value.contains("__armor")
        )
    });
    if !names_have_armor {
        return false;
    }
    head[0] == LOAD_GLOBAL_PRE_311 || head[0] == LOAD_GLOBAL_311_PLUS
}

pub(crate) fn strip_wrap(co: &mut CodeObject) -> bool {
    let stripped: bool = if has_wrap_header(co)
        && let (Some(header_len), Some(footer_len)) =
            (wrap_header_len(&co.code), wrap_footer_len(&co.code))
        && header_len + footer_len < co.code.len()
    {
        co.code.drain(..header_len);
        let new_len: usize = co.code.len();
        if new_len > footer_len {
            co.code.truncate(new_len - footer_len);
        }
        true
    } else {
        false
    };
    for cnst in &mut co.consts {
        if let Object::Code(inner) = cnst {
            let _ = strip_wrap(inner);
        }
    }
    stripped
}

fn wrap_header_len(code: &[u8]) -> Option<usize> {
    let mut i: usize = 0;
    while i + 1 < code.len() {
        match code[i] {
            CALL_FUNCTION => return Some(i + 2 + 2),
            SETUP_FINALLY => return Some(i + 2),
            _ => i += 2,
        }
        if i >= 16 {
            break;
        }
    }
    None
}

fn wrap_footer_len(code: &[u8]) -> Option<usize> {
    let mut i: usize = code.len();
    while i >= 2 {
        i -= 2;
        if code[i] == END_FINALLY {
            return Some(code.len() - i);
        }
        if code.len() - i >= 16 {
            break;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_py_marshal::CodeEra;

    fn fake_armor_co() -> CodeObject {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py38to310);
        co.code = vec![
            LOAD_GLOBAL_PRE_311,
            0,
            CALL_FUNCTION,
            0,
            POP_TOP,
            0,
            SETUP_FINALLY,
            4,
            0x60,
            0,
            0x53,
            0,
            END_FINALLY,
            0,
        ];
        co.names = vec![
            Object::ShortAscii {
                value: "__armor_enter__".to_owned(),
                interned: true,
            },
            Object::ShortAscii {
                value: "__armor_exit__".to_owned(),
                interned: true,
            },
        ];
        co
    }

    #[test]
    fn detects_wrap_header() {
        assert!(has_wrap_header(&fake_armor_co()));
    }

    #[test]
    fn strips_wrap_recursively() {
        let mut outer: CodeObject = fake_armor_co();
        let inner: CodeObject = fake_armor_co();
        outer.consts.push(Object::Code(Box::new(inner)));
        let stripped: bool = strip_wrap(&mut outer);
        assert!(stripped);
    }
}
