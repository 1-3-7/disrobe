use serde::{Deserialize, Serialize};

use crate::cil::{Instruction, MethodBody, parse_method_body};
use crate::cil_emulator::{StubInput, StubOutput, emulate_stub};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::static_decrypt::is_pure_transform;
use crate::signature::{TypeSig, TypeSigOrVoid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringDecryptor {
    pub method_token: u32,
    pub method_name: String,
    pub input_element: ArrayElement,
    pub body: MethodBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayElement {
    Byte,
    Char,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub method_token: u32,
    pub method_name: String,
    pub text: String,
}

const MAX_DECRYPTOR_INSTRUCTIONS: usize = 4096;

#[must_use]
pub fn find_string_decryptors(image: &[u8]) -> Vec<StringDecryptor> {
    let Ok(model): Result<AssemblyModel> = build_model(image) else {
        return Vec::new();
    };
    let Ok(pe): Result<PeImage> = parse(image) else {
        return Vec::new();
    };
    let mut found: Vec<StringDecryptor> = Vec::new();
    for ty in &model.types {
        collect_from_type(image, &pe, ty, &mut found);
    }
    found
}

fn build_model(image: &[u8]) -> Result<AssemblyModel> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    Ok(resolver.model())
}

fn collect_from_type(image: &[u8], pe: &PeImage, ty: &TypeModel, found: &mut Vec<StringDecryptor>) {
    for m in &ty.methods {
        let Some(input_element): Option<ArrayElement> = decryptor_shape(m) else {
            continue;
        };
        let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
            continue;
        };
        if m.rva == 0 || off >= image.len() {
            continue;
        }
        let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
            continue;
        };
        if body.instructions.len() > MAX_DECRYPTOR_INSTRUCTIONS || !is_pure_transform(&body) {
            continue;
        }
        if !returns_array(&body) {
            continue;
        }
        found.push(StringDecryptor {
            method_token: m.token,
            method_name: m.name.clone(),
            input_element,
            body,
        });
    }
}

fn decryptor_shape(m: &MethodModel) -> Option<ArrayElement> {
    if !m.is_static() || m.signature.params.len() != 1 {
        return None;
    }
    let input_element: ArrayElement = array_element(&m.signature.params[0])?;
    let TypeSigOrVoid::Type(ret): &TypeSigOrVoid = &m.signature.return_type else {
        return None;
    };
    array_element(ret)?;
    Some(input_element)
}

fn array_element(sig: &TypeSig) -> Option<ArrayElement> {
    let TypeSig::SzArray(inner): &TypeSig = sig else {
        return None;
    };
    match inner.as_ref() {
        TypeSig::U1 | TypeSig::I1 => Some(ArrayElement::Byte),
        TypeSig::Char | TypeSig::U2 | TypeSig::I2 => Some(ArrayElement::Char),
        _ => None,
    }
}

fn returns_array(body: &MethodBody) -> bool {
    body.instructions.iter().any(|ins: &Instruction| {
        matches!(
            ins.name.as_str(),
            "newarr" | "ldelem.i" | "stelem.i" | "stelem.i1" | "stelem.i2"
        )
    }) && has_return(body)
}

fn has_return(body: &MethodBody) -> bool {
    body.instructions
        .iter()
        .any(|ins: &Instruction| ins.name == "ret")
}

#[must_use]
pub fn decrypt_byte_input(decryptor: &StringDecryptor, cipher: &[u8]) -> Option<String> {
    let input: StubInput = StubInput {
        int_args: Vec::new(),
        byte_array_args: vec![cipher.to_vec()],
        char_array_args: Vec::new(),
    };
    decode(decryptor, input)
}

#[must_use]
pub fn decrypt_char_input(decryptor: &StringDecryptor, cipher: &[u16]) -> Option<String> {
    let input: StubInput = StubInput {
        int_args: Vec::new(),
        byte_array_args: Vec::new(),
        char_array_args: vec![cipher.to_vec()],
    };
    decode(decryptor, input)
}

#[must_use]
pub fn decrypt_text(decryptor: &StringDecryptor, cipher: &str) -> Option<String> {
    match decryptor.input_element {
        ArrayElement::Byte => decrypt_byte_input(decryptor, cipher.as_bytes()),
        ArrayElement::Char => {
            let units: Vec<u16> = cipher.encode_utf16().collect();
            decrypt_char_input(decryptor, &units)
        }
    }
}

fn decode(decryptor: &StringDecryptor, input: StubInput) -> Option<String> {
    match emulate_stub(&decryptor.body, &input).ok()? {
        StubOutput::Utf16(s) => Some(s),
        StubOutput::Bytes(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        StubOutput::Int(_) => None,
    }
}

const MIN_RECOVERED_LEN: usize = 1;
const MAX_RECOVERED_STRINGS: usize = 8192;

#[must_use]
pub fn looks_encrypted(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let len: usize = s.chars().count();
    let unreadable: usize = s
        .chars()
        .filter(|c: &char| !c.is_ascii_graphic() && !matches!(*c, ' ' | '\t' | '\n' | '\r'))
        .count();
    (unreadable as f64 / len as f64) > 0.30
}

#[must_use]
pub fn looks_readable(s: &str) -> bool {
    if s.chars().count() < MIN_RECOVERED_LEN {
        return false;
    }
    let len: usize = s.chars().count();
    let readable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || matches!(*c, ' ' | '\t' | '\n' | '\r'))
        .count();
    (readable as f64 / len as f64) > 0.85
}

#[must_use]
pub fn recover_emulated_strings(image: &[u8], ciphertexts: &[String]) -> Vec<RecoveredString> {
    let decryptors: Vec<StringDecryptor> = find_string_decryptors(image);
    if decryptors.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<RecoveredString> = Vec::new();
    for decryptor in &decryptors {
        for cipher in ciphertexts {
            if !looks_encrypted(cipher) {
                continue;
            }
            let Some(plain): Option<String> = decrypt_text(decryptor, cipher) else {
                continue;
            };
            if !looks_readable(&plain) || looks_encrypted(&plain) || &plain == cipher {
                continue;
            }
            if out.iter().any(|r: &RecoveredString| r.text == plain) {
                continue;
            }
            out.push(RecoveredString {
                method_token: decryptor.method_token,
                method_name: decryptor.method_name.clone(),
                text: plain,
            });
            if out.len() >= MAX_RECOVERED_STRINGS {
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    fn xor_char_array_decrypt_code(key: u16) -> Vec<u8> {
        let mut code: Vec<u8> = Vec::new();
        code.push(0x16);
        code.push(0x0A);
        let loop_start: i32 = code.len() as i32;
        code.push(0x02);
        code.push(0x06);
        code.push(0x02);
        code.push(0x06);
        code.push(0x93);
        code.push(0x20);
        code.extend_from_slice(&u32::from(key).to_le_bytes());
        code.push(0x61);
        code.push(0x9D);
        code.push(0x06);
        code.push(0x17);
        code.push(0x58);
        code.push(0x0A);
        code.push(0x06);
        code.push(0x02);
        code.push(0x8E);
        let blt_op_pos: i32 = code.len() as i32 + 1;
        let rel: i32 = loop_start - (blt_op_pos + 1);
        code.push(0x32);
        code.push(rel as u8);
        code.push(0x02);
        code.push(0x2A);
        code
    }

    #[test]
    fn emulated_char_array_decryptor_recovers_plaintext_from_ciphertext_only() {
        let key: u16 = 0x5C3A;
        let plain: &str = "connection-string-prod";
        let cipher: Vec<u16> = plain.encode_utf16().map(|c: u16| c ^ key).collect();
        let decryptor: StringDecryptor = StringDecryptor {
            method_token: 0x0600_0001,
            method_name: "Decrypt".to_string(),
            input_element: ArrayElement::Char,
            body: body_from(&xor_char_array_decrypt_code(key)),
        };
        let recovered: String = decrypt_char_input(&decryptor, &cipher).expect("decode");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_key_decryptor_does_not_yield_plaintext() {
        let key: u16 = 0x5C3A;
        let plain: &str = "connection-string-prod";
        let cipher: Vec<u16> = plain.encode_utf16().map(|c: u16| c ^ key).collect();
        let wrong: StringDecryptor = StringDecryptor {
            method_token: 0x0600_0001,
            method_name: "Decrypt".to_string(),
            input_element: ArrayElement::Char,
            body: body_from(&xor_char_array_decrypt_code(key ^ 0x0011)),
        };
        let recovered: String = decrypt_char_input(&wrong, &cipher).expect("decode");
        assert_ne!(recovered, plain);
    }

    #[test]
    fn shape_filter_rejects_non_array_signature() {
        let body: MethodBody = body_from(&[0x02, 0x2A]);
        assert!(!returns_array(&body));
    }
}
