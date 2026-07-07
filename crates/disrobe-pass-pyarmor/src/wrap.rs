use disrobe_py_marshal::{CodeObject, Object, PyVersion};

const LOAD_GLOBAL_PRE_311: u8 = 116;
const LOAD_GLOBAL_311_PLUS: u8 = 112;
const CALL_FUNCTION: u8 = 131;
const SETUP_FINALLY: u8 = 122;
const END_FINALLY: u8 = 88;

#[derive(Debug, Clone, Copy)]
struct RftOpcodes {
    nop: u8,
    pop_top: u8,
    push_null: u8,
    load_const: u8,
    store_fast: u8,
    store_name: u8,
    call: u8,
    call_function_ex: u8,
}

impl RftOpcodes {
    const fn for_version(py: PyVersion) -> Option<Self> {
        match (py.major, py.minor) {
            (3, 11 | 12) => Some(Self {
                nop: 9,
                pop_top: 1,
                push_null: 2,
                load_const: 100,
                store_fast: 125,
                store_name: 90,
                call: 171,
                call_function_ex: 142,
            }),
            (3, 13) => Some(Self {
                nop: 30,
                pop_top: 32,
                push_null: 34,
                load_const: 83,
                store_fast: 110,
                store_name: 114,
                call: 53,
                call_function_ex: 54,
            }),
            (3, 14) => Some(Self {
                nop: 27,
                pop_top: 31,
                push_null: 33,
                load_const: 82,
                store_fast: 112,
                store_name: 116,
                call: 52,
                call_function_ex: 4,
            }),
            _ => None,
        }
    }
}

const RFT_ENTER: &str = "__pyarmor_enter";
const RFT_EXIT: &str = "__pyarmor_exit";
const RFT_ASSERT: &str = "__pyarmor_assert";
const RFT_SCAN_WINDOW: usize = 30;

fn const_str(consts: &[Object], index: usize) -> Option<&str> {
    match consts.get(index)? {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

enum RftEdit {
    Nop {
        lo: usize,
        hi: usize,
    },
    MixStrCall {
        fn_lo: usize,
        arg_lo: usize,
        call_lo: usize,
        call_hi: usize,
        arg_const: usize,
    },
}

pub(crate) fn strip_rft_wrap(co: &mut CodeObject, py: PyVersion) -> usize {
    let Some(ops): Option<RftOpcodes> = RftOpcodes::for_version(py) else {
        return 0;
    };
    strip_rft_wrap_with(co, ops)
}

fn strip_rft_wrap_with(co: &mut CodeObject, ops: RftOpcodes) -> usize {
    let mut neutralized: usize = usize::from(neutralize_rft_body(co, ops));
    for cnst in &mut co.consts {
        if let Object::Code(inner) = cnst {
            neutralized += strip_rft_wrap_with(inner, ops);
        }
    }
    neutralized
}

fn neutralize_rft_body(co: &mut CodeObject, ops: RftOpcodes) -> bool {
    let len: usize = co.code.len();
    if len < 4 {
        return false;
    }
    let edits: Vec<RftEdit> = collect_rft_edits(&co.code, &co.consts, ops);
    if edits.is_empty() {
        return false;
    }
    for edit in edits {
        match edit {
            RftEdit::Nop { lo, hi } => nop_span(&mut co.code, lo, hi, ops.nop),
            RftEdit::MixStrCall {
                fn_lo,
                arg_lo,
                call_lo,
                call_hi,
                arg_const,
            } => {
                nop_span(&mut co.code, fn_lo, arg_lo, ops.nop);
                nop_span(&mut co.code, call_lo, call_hi, ops.nop);
                bytes_const_to_str(&mut co.consts, arg_const);
            }
        }
    }
    true
}

fn collect_rft_edits(code: &[u8], consts: &[Object], ops: RftOpcodes) -> Vec<RftEdit> {
    let len: usize = code.len();
    let mut edits: Vec<RftEdit> = Vec::new();
    let mut i: usize = 0;
    while i + 1 < len {
        if code[i] == ops.load_const
            && let Some(text) = const_str(consts, code[i + 1] as usize)
        {
            if text.starts_with(RFT_ENTER) || text.starts_with(RFT_EXIT) {
                if let Some(end) = rft_call_span_end(code, i, ops) {
                    edits.push(RftEdit::Nop { lo: i, hi: end });
                    i = end;
                    continue;
                }
            } else if text.starts_with(RFT_ASSERT) {
                let store: usize = i + 2;
                if store + 1 < len
                    && (code[store] == ops.store_fast || code[store] == ops.store_name)
                {
                    edits.push(RftEdit::Nop {
                        lo: i,
                        hi: store + 2,
                    });
                    i = store + 2;
                    continue;
                }
                if let Some(span) = mix_str_decode_span(code, i, ops) {
                    let next: usize = span.call_hi;
                    edits.push(RftEdit::MixStrCall {
                        fn_lo: i,
                        arg_lo: span.arg_lo,
                        call_lo: span.call_lo,
                        call_hi: span.call_hi,
                        arg_const: span.arg_const,
                    });
                    i = next;
                    continue;
                }
            }
        }
        i += 2;
    }
    edits
}

fn nop_span(code: &mut [u8], lo: usize, hi: usize, nop: u8) {
    let mut x: usize = lo;
    while x + 1 < hi {
        code[x] = nop;
        code[x + 1] = 0;
        x += 2;
    }
}

fn bytes_const_to_str(consts: &mut [Object], index: usize) {
    if let Some(Object::Bytes(raw)) = consts.get(index)
        && let Ok(text) = core::str::from_utf8(raw)
    {
        consts[index] = Object::Unicode {
            value: text.to_owned(),
            interned: false,
        };
    }
}

fn rft_call_span_end(code: &[u8], start: usize, ops: RftOpcodes) -> Option<usize> {
    let len: usize = code.len();
    let mut j: usize = start + 2;
    let limit: usize = (start + RFT_SCAN_WINDOW).min(len);
    while j + 1 < limit {
        if code[j] == ops.call || code[j] == ops.call_function_ex {
            let mut k: usize = j + 2;
            while k + 1 < len && code[k] == 0 {
                k += 2;
            }
            if k + 1 < len && code[k] == ops.pop_top {
                return Some(k + 2);
            }
            return None;
        }
        j += 2;
    }
    None
}

struct MixStrSpan {
    arg_lo: usize,
    call_lo: usize,
    call_hi: usize,
    arg_const: usize,
}

fn mix_str_decode_span(code: &[u8], fn_lo: usize, ops: RftOpcodes) -> Option<MixStrSpan> {
    let len: usize = code.len();
    let push_null: usize = fn_lo + 2;
    let arg_lo: usize = fn_lo + 4;
    let call_lo: usize = fn_lo + 6;
    if call_lo + 1 >= len {
        return None;
    }
    if code[push_null] != ops.push_null || code[arg_lo] != ops.load_const {
        return None;
    }
    if code[call_lo] != ops.call || code[call_lo + 1] != 1 {
        return None;
    }
    let mut call_hi: usize = call_lo + 2;
    while call_hi + 1 < len && code[call_hi] == 0 {
        call_hi += 2;
    }
    Some(MixStrSpan {
        arg_lo,
        call_lo,
        call_hi,
        arg_const: code[arg_lo + 1] as usize,
    })
}

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

    const PY314: PyVersion = PyVersion::new(3, 14);
    const POP_TOP_314: u8 = 31;
    const PUSH_NULL_314: u8 = 33;
    const LOAD_CONST_314: u8 = 82;
    const STORE_NAME_314: u8 = 116;
    const CALL_314: u8 = 52;
    const CALL_FUNCTION_EX_314: u8 = 4;

    fn ustr(value: &str) -> Object {
        Object::Unicode {
            value: value.to_owned(),
            interned: false,
        }
    }

    fn rft_module_314() -> CodeObject {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.consts = vec![
            ustr("__pyarmor_assert_37753__"),
            ustr("__pyarmor_enter_37754__"),
            Object::Bytes(vec![0u8; 21]),
            ustr("real_marker"),
            ustr("__pyarmor_exit_37755__"),
        ];
        co.code = vec![
            LOAD_CONST_314,
            1,
            PUSH_NULL_314,
            0,
            LOAD_CONST_314,
            2,
            CALL_FUNCTION_EX_314,
            0,
            POP_TOP_314,
            0,
            LOAD_CONST_314,
            0,
            STORE_NAME_314,
            0,
            LOAD_CONST_314,
            3,
            STORE_NAME_314,
            1,
            LOAD_CONST_314,
            4,
            PUSH_NULL_314,
            0,
            LOAD_CONST_314,
            2,
            CALL_314,
            1,
            POP_TOP_314,
            0,
        ];
        co
    }

    #[test]
    fn rft_neutralizes_enter_exit_and_assert_on_314() {
        let mut co: CodeObject = rft_module_314();
        let n: usize = strip_rft_wrap(&mut co, PY314);
        assert_eq!(n, 1, "one code object carried armor");
        for chunk in co.code.chunks_exact(2) {
            let op: u8 = chunk[0];
            if op == LOAD_CONST_314 {
                let idx: usize = chunk[1] as usize;
                assert_eq!(
                    idx, 3,
                    "the only surviving LOAD_CONST must load the real marker, not an armor constant"
                );
            }
            assert_ne!(op, CALL_FUNCTION_EX_314, "enter/exit call is NOPed out");
            assert_ne!(op, CALL_314, "trailing armor call is NOPed out");
        }
    }

    #[test]
    fn rft_leaves_offsets_and_length_unchanged() {
        let before: CodeObject = rft_module_314();
        let mut after: CodeObject = rft_module_314();
        let _ = strip_rft_wrap(&mut after, PY314);
        assert_eq!(
            before.code.len(),
            after.code.len(),
            "neutralization must not change bytecode length (offsets/exception table stay valid)"
        );
    }

    #[test]
    fn rft_collapses_mix_str_decode_to_bare_load() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.consts = vec![
            ustr("__pyarmor_assert_9__"),
            Object::Bytes(b"plaintext-secret".to_vec()),
        ];
        co.code = vec![
            LOAD_CONST_314,
            0,
            PUSH_NULL_314,
            0,
            LOAD_CONST_314,
            1,
            CALL_314,
            1,
            STORE_NAME_314,
            0,
        ];
        let n: usize = strip_rft_wrap(&mut co, PY314);
        assert_eq!(n, 1);
        assert!(
            matches!(&co.consts[1], Object::Unicode { value, .. } if value == "plaintext-secret"),
            "the decrypted mix-str bytes const is promoted to a str so the module assigns a real string"
        );
        let load_real: bool = co
            .code
            .chunks_exact(2)
            .any(|w: &[u8]| w[0] == LOAD_CONST_314 && w[1] == 1);
        assert!(load_real, "the plaintext string load survives the collapse");
        assert!(
            !co.code.chunks_exact(2).any(|w: &[u8]| w[0] == CALL_314),
            "the decode CALL is removed"
        );
    }

    #[test]
    fn rft_noop_on_unsupported_version() {
        let mut co: CodeObject = rft_module_314();
        let original: Vec<u8> = co.code.clone();
        let n: usize = strip_rft_wrap(&mut co, PyVersion::new(3, 8));
        assert_eq!(n, 0, "no opcode table for 3.8; RFT strip is a no-op");
        assert_eq!(co.code, original);
    }

    #[test]
    fn rft_leaves_clean_code_untouched() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.consts = vec![ustr("hello"), Object::Int(1)];
        co.code = vec![LOAD_CONST_314, 0, STORE_NAME_314, 0];
        let original: Vec<u8> = co.code.clone();
        let n: usize = strip_rft_wrap(&mut co, PY314);
        assert_eq!(n, 0, "code with no armor constants is not touched");
        assert_eq!(co.code, original);
    }
}
