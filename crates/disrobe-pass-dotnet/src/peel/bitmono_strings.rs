use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use disrobe_core::codec::{CbcPadding, aes_cbc_decrypt};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::debug::{dbg_kv, dbg_line};
use crate::metadata::{MetadataRoot, metadata_slice, parse_metadata_root};
use crate::model::Resolver;
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::cctor_constants::int_immediate;
use crate::peel::deflatten::decrypt::init_array_tokens;
use crate::signature::{MethodSig, TypeSig, TypeSigOrVoid};
use crate::tables::{AssemblyRefRow, MemberRefRow, MethodDefRow, RowRef, TableId, TypeRefRow};

const FIELD_TABLE: u32 = 0x0400_0000;
const METHOD_DEF_TABLE: u32 = 0x0600_0000;
const MEMBER_REF_TABLE: u32 = 0x0A00_0000;
const TABLE_MASK: u32 = 0xFF00_0000;
const RID_MASK: u32 = 0x00FF_FFFF;

const CRYPTOGRAPHY_NAMESPACE: &str = "System.Security.Cryptography";
const DERIVE_BYTES_TYPE: &str = "Rfc2898DeriveBytes";
const CIPHER_MODE_CBC: i64 = 1;
const AES_IV_BITS: u32 = 128;

const MAX_ARRAY_FIELD_BYTES: usize = 1 << 20;
const MAX_CIPHERTEXT_BYTES: usize = 1 << 16;
const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;
const MAX_CALL_SITES: usize = 4096;
const MAX_DECRYPTOR_INSTRUCTIONS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitMonoDecryptorShape {
    pub method_token: u32,
    pub data_arg: u8,
    pub salt_arg: u8,
    pub password_arg: u8,
    pub key_size_bits: u32,
    pub block_size_bits: u32,
    pub iterations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitMonoRecoveredString {
    pub caller_token: u32,
    pub call_offset: u32,
    pub data_field: u32,
    pub salt_field: u32,
    pub password_field: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitMonoStringRecovery {
    pub shape: BitMonoDecryptorShape,
    pub recovered: Vec<BitMonoRecoveredString>,
    pub call_sites_total: u32,
    pub call_sites_unresolved: u32,
}

#[must_use]
pub fn recover_bitmono_strings(image: &[u8]) -> Option<BitMonoStringRecovery> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    let metadata: &[u8] = metadata_slice(image, &pe, &clr, &root).ok()?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).ok()?;
    let blob: &[u8] = root
        .streams
        .get("#Blob")
        .and_then(|h: &crate::metadata::StreamHeader| {
            let start: usize = h.offset as usize;
            let end: usize = start.saturating_add(h.size as usize).min(metadata.len());
            metadata.get(start..end)
        })
        .unwrap_or(&[]);

    let bodies: Vec<(u32, MethodBody)> = method_bodies(image, &pe, &resolver);
    let shape: BitMonoDecryptorShape = locate_decryptor(&resolver, &bodies)?;
    let arrays: BTreeMap<u32, Vec<u8>> = array_field_data(image, &pe, &resolver, blob, &bodies);

    let mut recovered: Vec<BitMonoRecoveredString> = Vec::new();
    let mut cache: DerivationCache = DerivationCache::new();
    let mut call_sites_total: u32 = 0;
    let mut call_sites_unresolved: u32 = 0;
    for (caller_token, body) in &bodies {
        if *caller_token == shape.method_token {
            continue;
        }
        for site in call_sites(body, shape.method_token, &arrays) {
            if call_sites_total as usize >= MAX_CALL_SITES {
                break;
            }
            call_sites_total += 1;
            match decrypt_site(&shape, &arrays, &mut cache, &site) {
                Some(text) => recovered.push(BitMonoRecoveredString {
                    caller_token: *caller_token,
                    call_offset: site.offset,
                    data_field: site.args[usize::from(shape.data_arg)],
                    salt_field: site.args[usize::from(shape.salt_arg)],
                    password_field: site.args[usize::from(shape.password_arg)],
                    text,
                }),
                None => call_sites_unresolved += 1,
            }
        }
    }
    Some(BitMonoStringRecovery {
        shape,
        recovered,
        call_sites_total,
        call_sites_unresolved,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StringCallSite {
    offset: u32,
    args: [u32; 3],
}

fn method_bodies(image: &[u8], pe: &PeImage, resolver: &Resolver) -> Vec<(u32, MethodBody)> {
    let mut out: Vec<(u32, MethodBody)> = Vec::new();
    for (index, row) in resolver.tables().methods.iter().enumerate() {
        let rid: u32 = match u32::try_from(index + 1) {
            Ok(value) => value,
            Err(_) => break,
        };
        if row.rva == 0 {
            continue;
        }
        let Some(offset): Option<usize> = pe.rva_to_offset(row.rva) else {
            continue;
        };
        let Some(tail): Option<&[u8]> = image.get(offset..) else {
            continue;
        };
        let Ok(body): crate::error::Result<MethodBody> = parse_method_body(tail) else {
            continue;
        };
        if body.instructions.len() > MAX_DECRYPTOR_INSTRUCTIONS {
            continue;
        }
        out.push((METHOD_DEF_TABLE | rid, body));
    }
    out
}

fn member_name(resolver: &Resolver, token: u32) -> Option<String> {
    let rid: u32 = token & RID_MASK;
    if rid == 0 {
        return None;
    }
    let index: usize = usize::try_from(rid - 1).ok()?;
    match token & TABLE_MASK {
        MEMBER_REF_TABLE => {
            let row: &MemberRefRow = resolver.tables().member_refs.get(index)?;
            Some(resolver.string(row.name))
        }
        METHOD_DEF_TABLE => {
            let row: &MethodDefRow = resolver.tables().methods.get(index)?;
            Some(resolver.string(row.name))
        }
        _ => None,
    }
}

fn member_ref_parent(resolver: &Resolver, token: u32) -> Option<RowRef> {
    if token & TABLE_MASK != MEMBER_REF_TABLE {
        return None;
    }
    let rid: u32 = token & RID_MASK;
    let index: usize = usize::try_from(rid.checked_sub(1)?).ok()?;
    resolver.tables().member_refs.get(index)?.parent
}

const PLATFORM_PUBLIC_KEY_TOKENS: [[u8; 8]; 3] = [
    [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89],
    [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A],
    [0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E],
];

fn is_platform_type_ref(
    resolver: &Resolver,
    type_ref: RowRef,
    namespace: &str,
    name: &str,
) -> bool {
    if type_ref.table != TableId::TypeRef {
        return false;
    }
    let Some(index): Option<usize> = type_ref.row.checked_sub(1).map(|row: u32| row as usize)
    else {
        return false;
    };
    let Some(row): Option<&TypeRefRow> = resolver.tables().type_refs.get(index) else {
        return false;
    };
    if resolver.string(row.namespace) != namespace || resolver.string(row.name) != name {
        return false;
    }
    let Some(scope): Option<RowRef> = row.resolution_scope else {
        return false;
    };
    if scope.table != TableId::AssemblyRef {
        return false;
    }
    let Some(scope_index): Option<usize> = scope.row.checked_sub(1).map(|row: u32| row as usize)
    else {
        return false;
    };
    let Some(assembly): Option<&AssemblyRefRow> = resolver.tables().assembly_refs.get(scope_index)
    else {
        return false;
    };
    resolver
        .blob(assembly.public_key_or_token)
        .is_some_and(|token: &[u8]| {
            PLATFORM_PUBLIC_KEY_TOKENS
                .iter()
                .any(|known: &[u8; 8]| known == token)
        })
}

fn arg_index(ins: &Instruction) -> Option<u8> {
    match (ins.name.as_str(), &ins.operand) {
        ("ldarg.0", _) => Some(0),
        ("ldarg.1", _) => Some(1),
        ("ldarg.2", _) => Some(2),
        ("ldarg.3", _) => Some(3),
        ("ldarg.s", OperandValue::U8(index)) => Some(*index),
        ("ldarg", OperandValue::U16(index)) => u8::try_from(*index).ok(),
        _ => None,
    }
}

fn call_token(ins: &Instruction, mnemonics: &[&str]) -> Option<u32> {
    if !mnemonics.contains(&ins.name.as_str()) {
        return None;
    }
    match ins.operand {
        OperandValue::Token(token) => Some(token),
        _ => None,
    }
}

fn setter_immediate(resolver: &Resolver, body: &MethodBody, setter: &str) -> Option<i64> {
    body.instructions
        .windows(3)
        .find_map(|window: &[Instruction]| {
            let value: i64 = int_immediate(&window[1])?;
            let token: u32 = call_token(&window[2], &["callvirt", "call"])?;
            (member_name(resolver, token)?.as_str() == setter).then_some(value)
        })
}

fn calls_member(resolver: &Resolver, body: &MethodBody, name: &str) -> bool {
    body.instructions.iter().any(|ins: &Instruction| {
        call_token(ins, &["callvirt", "call", "newobj"])
            .and_then(|token: u32| member_name(resolver, token))
            .is_some_and(|found: String| found == name)
    })
}

fn derive_bytes_construction(resolver: &Resolver, body: &MethodBody) -> Option<(u8, u8, u32)> {
    body.instructions
        .windows(4)
        .find_map(|window: &[Instruction]| {
            let password: u8 = arg_index(&window[0])?;
            let salt: u8 = arg_index(&window[1])?;
            let iterations: i64 = int_immediate(&window[2])?;
            let token: u32 = call_token(&window[3], &["newobj"])?;
            if member_name(resolver, token)?.as_str() != ".ctor" {
                return None;
            }
            let parent: RowRef = member_ref_parent(resolver, token)?;
            if !is_platform_type_ref(resolver, parent, CRYPTOGRAPHY_NAMESPACE, DERIVE_BYTES_TYPE) {
                return None;
            }
            let signature: MethodSig = resolver.callee_signature(token)?;
            if signature.params.len() != 3 || password == salt {
                return None;
            }
            let iterations: u32 = u32::try_from(iterations).ok()?;
            (iterations > 0 && iterations <= MAX_PBKDF2_ITERATIONS)
                .then_some((password, salt, iterations))
        })
}

fn decryptor_signature_arity(signature: &MethodSig) -> bool {
    let byte_arrays: usize = signature
        .params
        .iter()
        .filter(|param: &&TypeSig| matches!(param, TypeSig::SzArray(inner) if matches!(inner.as_ref(), TypeSig::U1 | TypeSig::I1)))
        .count();
    let returns_string: bool =
        matches!(&signature.return_type, TypeSigOrVoid::Type(TypeSig::String));
    signature.params.len() == 3 && byte_arrays == 3 && returns_string && !signature.has_this
}

fn locate_decryptor(
    resolver: &Resolver,
    bodies: &[(u32, MethodBody)],
) -> Option<BitMonoDecryptorShape> {
    for (token, body) in bodies {
        let Some(signature): Option<MethodSig> = resolver.callee_signature(*token) else {
            continue;
        };
        if !decryptor_signature_arity(&signature) {
            continue;
        }
        dbg_kv("bitmono-decryptor-candidate", || {
            format!(
                "token=0x{token:08x} instructions={}",
                body.instructions.len()
            )
        });
        let Some((password_arg, salt_arg, iterations)): Option<(u8, u8, u32)> =
            derive_bytes_construction(resolver, body)
        else {
            dbg_line(|| {
                format!("token=0x{token:08x} rejected: no Rfc2898DeriveBytes construction")
            });
            continue;
        };
        if setter_immediate(resolver, body, "set_Mode") != Some(CIPHER_MODE_CBC) {
            dbg_line(|| format!("token=0x{token:08x} rejected: cipher mode is not CBC"));
            continue;
        }
        if !calls_member(resolver, body, "set_Key")
            || !calls_member(resolver, body, "set_IV")
            || !calls_member(resolver, body, "CreateDecryptor")
            || !calls_member(resolver, body, "GetBytes")
            || !calls_member(resolver, body, "GetString")
        {
            dbg_line(|| format!("token=0x{token:08x} rejected: incomplete decrypt call set"));
            continue;
        }
        let Some(data_arg): Option<u8> = [0u8, 1u8, 2u8]
            .into_iter()
            .find(|candidate: &u8| *candidate != password_arg && *candidate != salt_arg)
        else {
            continue;
        };
        if !body
            .instructions
            .iter()
            .any(|ins: &Instruction| ins.name == "ldlen")
        {
            continue;
        }
        let key_size_bits: u32 = setter_immediate(resolver, body, "set_KeySize")
            .and_then(|bits: i64| u32::try_from(bits).ok())
            .unwrap_or(0);
        let block_size_bits: u32 = setter_immediate(resolver, body, "set_BlockSize")
            .and_then(|bits: i64| u32::try_from(bits).ok())
            .unwrap_or(AES_IV_BITS);
        if !matches!(key_size_bits, 128 | 192 | 256) || block_size_bits != AES_IV_BITS {
            dbg_line(|| {
                format!("token=0x{token:08x} rejected: key={key_size_bits} block={block_size_bits}")
            });
            continue;
        }
        return Some(BitMonoDecryptorShape {
            method_token: *token,
            data_arg,
            salt_arg,
            password_arg,
            key_size_bits,
            block_size_bits,
            iterations,
        });
    }
    None
}

fn array_field_data(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    blob: &[u8],
    bodies: &[(u32, MethodBody)],
) -> BTreeMap<u32, Vec<u8>> {
    let init_array: std::collections::BTreeSet<u32> = init_array_tokens(resolver, blob);
    let mut out: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (_, body) in bodies {
        for window in body.instructions.windows(6) {
            let Some(length): Option<i64> = int_immediate(&window[0]) else {
                continue;
            };
            if call_token(&window[1], &["newarr"]).is_none() || window[2].name != "dup" {
                continue;
            }
            let Some(data_field): Option<u32> = call_token(&window[3], &["ldtoken"]) else {
                continue;
            };
            let Some(initializer): Option<u32> = call_token(&window[4], &["call"]) else {
                continue;
            };
            let Some(array_field): Option<u32> = call_token(&window[5], &["stsfld"]) else {
                continue;
            };
            if !init_array.contains(&initializer)
                || data_field & TABLE_MASK != FIELD_TABLE
                || array_field & TABLE_MASK != FIELD_TABLE
            {
                continue;
            }
            let Ok(length): std::result::Result<usize, _> = usize::try_from(length) else {
                continue;
            };
            if length == 0 || length > MAX_ARRAY_FIELD_BYTES {
                continue;
            }
            if let Some(bytes) = field_rva_bytes(image, pe, resolver, data_field, length) {
                out.insert(array_field, bytes);
            }
        }
    }
    out
}

fn field_rva_bytes(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    field_token: u32,
    length: usize,
) -> Option<Vec<u8>> {
    let rid: u32 = field_token & RID_MASK;
    let mut found: Option<u32> = None;
    for row in &resolver.tables().field_rvas {
        if row.field != rid {
            continue;
        }
        if found.is_some_and(|rva: u32| rva != row.rva) {
            return None;
        }
        found = Some(row.rva);
    }
    let rva: u32 = found?;
    let offset: usize = pe.rva_to_offset(rva)?;
    image
        .get(offset..offset.checked_add(length)?)
        .map(<[u8]>::to_vec)
}

const ARGUMENT_LOOKBACK_INSTRUCTIONS: usize = 64;

fn call_sites(
    body: &MethodBody,
    decryptor: u32,
    arrays: &BTreeMap<u32, Vec<u8>>,
) -> Vec<StringCallSite> {
    let mut out: Vec<StringCallSite> = Vec::new();
    for (index, ins) in body.instructions.iter().enumerate() {
        if call_token(ins, &["call"]) != Some(decryptor) {
            continue;
        }
        let start: usize = index.saturating_sub(ARGUMENT_LOOKBACK_INSTRUCTIONS);
        let mut loads: Vec<u32> = Vec::with_capacity(3);
        for earlier in body.instructions[start..index].iter().rev() {
            let Some(field): Option<u32> = call_token(earlier, &["ldsfld"]) else {
                continue;
            };
            if !arrays.contains_key(&field) {
                continue;
            }
            loads.push(field);
            if loads.len() == 3 {
                break;
            }
        }
        let args: [u32; 3] = match loads.as_slice() {
            [last_pushed, middle, first_pushed] => [*first_pushed, *middle, *last_pushed],
            _ => continue,
        };
        out.push(StringCallSite {
            offset: ins.offset,
            args,
        });
    }
    out
}

const MAX_DERIVATIONS: usize = 32;

type DerivationCache = BTreeMap<(Vec<u8>, Vec<u8>), Vec<u8>>;

fn decrypt_site(
    shape: &BitMonoDecryptorShape,
    arrays: &BTreeMap<u32, Vec<u8>>,
    cache: &mut DerivationCache,
    site: &StringCallSite,
) -> Option<String> {
    let data: &Vec<u8> = arrays.get(&site.args[usize::from(shape.data_arg)])?;
    let salt: &Vec<u8> = arrays.get(&site.args[usize::from(shape.salt_arg)])?;
    let password: &Vec<u8> = arrays.get(&site.args[usize::from(shape.password_arg)])?;
    if data.is_empty() || data.len() > MAX_CIPHERTEXT_BYTES {
        return None;
    }
    let key_len: usize = usize::try_from(shape.key_size_bits / 8).ok()?;
    let iv_len: usize = usize::try_from(shape.block_size_bits / 8).ok()?;
    let material: (Vec<u8>, Vec<u8>) = (password.clone(), salt.clone());
    let at_capacity: bool = cache.len() >= MAX_DERIVATIONS;
    let derived: &Vec<u8> = match cache.entry(material) {
        Entry::Occupied(existing) => existing.into_mut(),
        Entry::Vacant(slot) => {
            if at_capacity {
                return None;
            }
            let mut fresh: Vec<u8> = vec![0u8; key_len.checked_add(iv_len)?];
            pbkdf2_hmac::<Sha1>(password, salt, shape.iterations, &mut fresh);
            slot.insert(fresh)
        }
    };
    let (key, iv): (&[u8], &[u8]) = derived.split_at_checked(key_len)?;
    let plain: Vec<u8> = aes_cbc_decrypt(key, iv, data, CbcPadding::Pkcs7).ok()?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rfc6070_pbkdf2_hmac_sha1_vector_matches_published_answer() {
        let mut out: Vec<u8> = vec![0u8; 20];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out,
            [
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
                0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
            ],
            "RFC 6070 test case 3 pins the PBKDF2-HMAC-SHA1 stream this recovery derives keys with"
        );
    }

    #[test]
    fn split_derivation_is_one_continuous_pbkdf2_stream() {
        let mut whole: Vec<u8> = vec![0u8; 48];
        pbkdf2_hmac::<Sha1>(b"pw", b"salt", 1000, &mut whole);
        let mut key: Vec<u8> = vec![0u8; 32];
        pbkdf2_hmac::<Sha1>(b"pw", b"salt", 1000, &mut key);
        assert_eq!(
            &whole[..32],
            key.as_slice(),
            "a 32-byte request must be the prefix of a 48-byte request, which is what makes \
             GetBytes(32) followed by GetBytes(16) equal to one 48-byte derivation"
        );
    }
}
