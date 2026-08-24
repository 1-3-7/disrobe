#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};

use crate::dalvik_to_jvm::{EmittedCode, emit_branch_method_code, emit_method_code};
use crate::dex::{CodeItem, DexFile, parse_code_items};
use crate::error::{Error, Result};

const ACC_INTERFACE: u16 = 0x0200;
const ACC_ABSTRACT: u16 = 0x0400;
const ACC_NATIVE: u16 = 0x0100;
const ACC_STATIC: u16 = 0x0008;
const ACC_SUPER: u16 = 0x0020;
const CLASS_VERSION_MAJOR: u16 = 52;
const CLASS_VERSION_MINOR: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedMethod {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    pub has_code: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedField {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedClass {
    pub internal_name: String,
    pub super_name: String,
    pub interfaces: Vec<String>,
    pub access_flags: u16,
    pub fields: Vec<TranslatedField>,
    pub methods: Vec<TranslatedMethod>,
}

impl TranslatedClass {
    #[inline]
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & ACC_INTERFACE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dex2JarResult {
    pub classes: Vec<TranslatedClass>,
    pub jar_entries: BTreeMap<String, Vec<u8>>,
    pub method_total: usize,
    pub bodies_recovered: usize,
    pub stubbed_body_count: usize,
    #[serde(default)]
    pub code_scan_complete: bool,
    #[serde(default)]
    pub decode_error_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dex2JarLimits {
    pub classes: usize,
    pub class_bytes: usize,
    pub jar_bytes: usize,
}

impl Default for Dex2JarLimits {
    fn default() -> Self {
        Self {
            classes: 65_536,
            class_bytes: 128 * 1024 * 1024,
            jar_bytes: 128 * 1024 * 1024,
        }
    }
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    position: u64,
    logical_len: u64,
    overflowed: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let byte_count: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next: u64 = self.position.saturating_add(byte_count);
        let limit: u64 = u64::try_from(self.limit).unwrap_or(u64::MAX);
        let retained_start: usize = usize::try_from(self.position.min(limit)).unwrap_or(self.limit);
        let retained_end: usize = usize::try_from(next.min(limit)).unwrap_or(self.limit);
        if retained_end > retained_start {
            if retained_end > self.bytes.len() {
                self.bytes.resize(retained_end, 0);
            }
            self.bytes[retained_start..retained_end]
                .copy_from_slice(&bytes[..retained_end - retained_start]);
        }
        self.overflowed |= next > limit;
        self.position = next;
        self.logical_len = self.logical_len.max(next);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for LimitedWriter {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let base: i128 = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.logical_len) + i128::from(n),
        };
        let next: u64 = u64::try_from(base).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "DEX-to-JAR seek overflow")
        })?;
        self.position = next;
        Ok(next)
    }
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_uleb128(bytes: &[u8], off: usize) -> Option<(u32, usize)> {
    crate::dex::read_uleb128(bytes, off).ok()
}

fn dex_type_to_internal(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].to_string()
    } else {
        descriptor.to_string()
    }
}

fn parse_type_list(dex_bytes: &[u8], off: usize, type_names: &[String]) -> Vec<String> {
    if off == 0 {
        return Vec::new();
    }
    let Some(size): Option<u32> = read_u32(dex_bytes, off) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity((size as usize).min(dex_bytes.len() / 2));
    for i in 0..size as usize {
        let entry_off: usize = off + 4 + i * 2;
        let Some(s): Option<&[u8]> = dex_bytes.get(entry_off..entry_off + 2) else {
            break;
        };
        let type_idx: usize = u16::from_le_bytes([s[0], s[1]]) as usize;
        if let Some(name) = type_names.get(type_idx) {
            out.push(dex_type_to_internal(name));
        }
    }
    out
}

pub fn build_class_model(dex: &DexFile, dex_bytes: &[u8]) -> Vec<TranslatedClass> {
    let header: &crate::dex::DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let mut classes: Vec<TranslatedClass> =
        Vec::with_capacity((header.class_defs_size as usize).min(dex_bytes.len() / 32));
    for ci in 0..header.class_defs_size as usize {
        let base: usize = class_defs_off + ci * 32;
        let Some(class_idx): Option<u32> = read_u32(dex_bytes, base) else {
            break;
        };
        let Some(access_flags): Option<u32> = read_u32(dex_bytes, base + 4) else {
            break;
        };
        let Some(superclass_idx): Option<u32> = read_u32(dex_bytes, base + 8) else {
            break;
        };
        let Some(interfaces_off): Option<u32> = read_u32(dex_bytes, base + 12) else {
            break;
        };
        let Some(class_data_off): Option<u32> = read_u32(dex_bytes, base + 24) else {
            break;
        };
        let internal_name: String = dex
            .type_names
            .get(class_idx as usize)
            .map(|s: &String| dex_type_to_internal(s))
            .unwrap_or_default();
        if internal_name.is_empty() {
            continue;
        }
        let super_name: String = if superclass_idx == 0xFFFF_FFFF {
            "java/lang/Object".to_string()
        } else {
            dex.type_names
                .get(superclass_idx as usize)
                .map(|s: &String| dex_type_to_internal(s))
                .unwrap_or_else(|| "java/lang/Object".to_string())
        };
        let interfaces: Vec<String> =
            parse_type_list(dex_bytes, interfaces_off as usize, &dex.type_names);
        let (fields, methods): (Vec<TranslatedField>, Vec<TranslatedMethod>) =
            if class_data_off == 0 {
                (Vec::new(), Vec::new())
            } else {
                parse_class_data(dex, dex_bytes, class_data_off as usize)
            };
        classes.push(TranslatedClass {
            internal_name,
            super_name,
            interfaces,
            access_flags: access_flags as u16,
            fields,
            methods,
        });
    }
    classes
}

fn parse_class_data(
    dex: &DexFile,
    bytes: &[u8],
    off: usize,
) -> (Vec<TranslatedField>, Vec<TranslatedMethod>) {
    let Some((static_fields, o1)): Option<(u32, usize)> = read_uleb128(bytes, off) else {
        return (Vec::new(), Vec::new());
    };
    let Some((instance_fields, o2)): Option<(u32, usize)> = read_uleb128(bytes, o1) else {
        return (Vec::new(), Vec::new());
    };
    let Some((direct_methods, o3)): Option<(u32, usize)> = read_uleb128(bytes, o2) else {
        return (Vec::new(), Vec::new());
    };
    let Some((virtual_methods, o4)): Option<(u32, usize)> = read_uleb128(bytes, o3) else {
        return (Vec::new(), Vec::new());
    };
    let mut fields: Vec<TranslatedField> = Vec::new();
    let mut cursor: usize = o4;
    cursor = read_encoded_fields(dex, bytes, cursor, static_fields, &mut fields);
    cursor = read_encoded_fields(dex, bytes, cursor, instance_fields, &mut fields);
    let mut methods: Vec<TranslatedMethod> = Vec::new();
    cursor = read_encoded_methods(dex, bytes, cursor, direct_methods, &mut methods);
    let _ = read_encoded_methods(dex, bytes, cursor, virtual_methods, &mut methods);
    (fields, methods)
}

fn read_encoded_fields(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    out: &mut Vec<TranslatedField>,
) -> usize {
    let mut field_idx: u32 = 0;
    for k in 0..count {
        let Some((idx_diff, n1)): Option<(u32, usize)> = read_uleb128(bytes, o) else {
            return o;
        };
        let Some((access, n2)): Option<(u32, usize)> = read_uleb128(bytes, n1) else {
            return n1;
        };
        field_idx = if k == 0 {
            idx_diff
        } else {
            field_idx + idx_diff
        };
        if let Some(field) = dex.field_ids.get(field_idx as usize) {
            out.push(TranslatedField {
                name: field.name.clone(),
                descriptor: field.type_name.clone(),
                access_flags: access as u16,
            });
        }
        o = n2;
    }
    o
}

fn read_encoded_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    out: &mut Vec<TranslatedMethod>,
) -> usize {
    let mut method_idx: u32 = 0;
    for k in 0..count {
        let Some((idx_diff, n1)): Option<(u32, usize)> = read_uleb128(bytes, o) else {
            return o;
        };
        let Some((access, n2)): Option<(u32, usize)> = read_uleb128(bytes, n1) else {
            return n1;
        };
        let Some((code_off, n3)): Option<(u32, usize)> = read_uleb128(bytes, n2) else {
            return n2;
        };
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx + idx_diff
        };
        if let Some(method) = dex.method_ids.get(method_idx as usize) {
            let params: String = method.proto.parameters.concat();
            let descriptor: String = format!("({params}){}", method.proto.return_type);
            out.push(TranslatedMethod {
                name: method.name.clone(),
                descriptor,
                access_flags: access as u16,
                has_code: code_off != 0,
            });
        }
        o = n3;
    }
    o
}

#[derive(Default)]
pub(crate) struct ConstantPool {
    entries: Vec<Vec<u8>>,
    utf8: BTreeMap<String, u16>,
    class: BTreeMap<String, u16>,
    name_and_type: BTreeMap<(u16, u16), u16>,
    methodref: BTreeMap<(u8, u16, u16), u16>,
    fieldref: BTreeMap<(u16, u16), u16>,
    string: BTreeMap<String, u16>,
    integer: BTreeMap<i32, u16>,
    long: BTreeMap<i64, u16>,
    float: BTreeMap<u32, u16>,
    double: BTreeMap<u64, u16>,
}

impl ConstantPool {
    pub(crate) fn overflowed(&self) -> bool {
        self.entries.len() >= usize::from(u16::MAX)
    }

    const fn next_index(&self) -> u16 {
        (self.entries.len() + 1) as u16
    }

    fn push_wide(&mut self, entry: Vec<u8>) -> u16 {
        let idx: u16 = self.next_index();
        self.entries.push(entry);
        self.entries.push(Vec::new());
        idx
    }

    pub(crate) fn utf8(&mut self, s: &str) -> u16 {
        if let Some(i) = self.utf8.get(s) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let bytes: &[u8] = s.as_bytes();
        let mut entry: Vec<u8> = Vec::with_capacity(3 + bytes.len());
        entry.push(1);
        entry.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        entry.extend_from_slice(bytes);
        self.entries.push(entry);
        self.utf8.insert(s.to_string(), idx);
        idx
    }

    fn class(&mut self, internal: &str) -> u16 {
        if let Some(i) = self.class.get(internal) {
            return *i;
        }
        let name_idx: u16 = self.utf8(internal);
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(3);
        entry.push(7);
        entry.extend_from_slice(&name_idx.to_be_bytes());
        self.entries.push(entry);
        self.class.insert(internal.to_string(), idx);
        idx
    }

    fn name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let n: u16 = self.utf8(name);
        let d: u16 = self.utf8(descriptor);
        if let Some(i) = self.name_and_type.get(&(n, d)) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(5);
        entry.push(12);
        entry.extend_from_slice(&n.to_be_bytes());
        entry.extend_from_slice(&d.to_be_bytes());
        self.entries.push(entry);
        self.name_and_type.insert((n, d), idx);
        idx
    }

    pub(crate) fn methodref(&mut self, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        self.member_ref(10, class_internal, name, descriptor)
    }

    pub(crate) fn interface_methodref(
        &mut self,
        class_internal: &str,
        name: &str,
        descriptor: &str,
    ) -> u16 {
        self.member_ref(11, class_internal, name, descriptor)
    }

    fn member_ref(&mut self, tag: u8, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        let c: u16 = self.class(class_internal);
        let nt: u16 = self.name_and_type(name, descriptor);
        if let Some(i) = self.methodref.get(&(tag, c, nt)) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(5);
        entry.push(tag);
        entry.extend_from_slice(&c.to_be_bytes());
        entry.extend_from_slice(&nt.to_be_bytes());
        self.entries.push(entry);
        self.methodref.insert((tag, c, nt), idx);
        idx
    }

    pub(crate) fn fieldref(&mut self, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        let c: u16 = self.class(class_internal);
        let nt: u16 = self.name_and_type(name, descriptor);
        if let Some(i) = self.fieldref.get(&(c, nt)) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(5);
        entry.push(9);
        entry.extend_from_slice(&c.to_be_bytes());
        entry.extend_from_slice(&nt.to_be_bytes());
        self.entries.push(entry);
        self.fieldref.insert((c, nt), idx);
        idx
    }

    pub(crate) fn string(&mut self, s: &str) -> u16 {
        if let Some(i) = self.string.get(s) {
            return *i;
        }
        let utf8_idx: u16 = self.utf8(s);
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(3);
        entry.push(8);
        entry.extend_from_slice(&utf8_idx.to_be_bytes());
        self.entries.push(entry);
        self.string.insert(s.to_string(), idx);
        idx
    }

    pub(crate) fn class_const(&mut self, internal: &str) -> u16 {
        self.class(internal)
    }

    pub(crate) fn integer(&mut self, value: i32) -> u16 {
        if let Some(i) = self.integer.get(&value) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(5);
        entry.push(3);
        entry.extend_from_slice(&value.to_be_bytes());
        self.entries.push(entry);
        self.integer.insert(value, idx);
        idx
    }

    pub(crate) fn long(&mut self, value: i64) -> u16 {
        if let Some(i) = self.long.get(&value) {
            return *i;
        }
        let mut entry: Vec<u8> = Vec::with_capacity(9);
        entry.push(5);
        entry.extend_from_slice(&value.to_be_bytes());
        let idx: u16 = self.push_wide(entry);
        self.long.insert(value, idx);
        idx
    }

    pub(crate) fn float_bits(&mut self, bits: u32) -> u16 {
        if let Some(i) = self.float.get(&bits) {
            return *i;
        }
        let idx: u16 = self.next_index();
        let mut entry: Vec<u8> = Vec::with_capacity(5);
        entry.push(4);
        entry.extend_from_slice(&bits.to_be_bytes());
        self.entries.push(entry);
        self.float.insert(bits, idx);
        idx
    }

    pub(crate) fn double_bits(&mut self, bits: u64) -> u16 {
        if let Some(i) = self.double.get(&bits) {
            return *i;
        }
        let mut entry: Vec<u8> = Vec::with_capacity(9);
        entry.push(6);
        entry.extend_from_slice(&bits.to_be_bytes());
        let idx: u16 = self.push_wide(entry);
        self.double.insert(bits, idx);
        idx
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&self.next_index().to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(entry);
        }
        out
    }
}

fn descriptor_return_is_void(descriptor: &str) -> bool {
    descriptor.rsplit(')').next() == Some("V")
}

fn stub_code(cp: &mut ConstantPool) -> (Vec<u8>, u16) {
    let uoe_ctor: u16 = cp.methodref("java/lang/UnsupportedOperationException", "<init>", "()V");
    let uoe_class: u16 = cp.class("java/lang/UnsupportedOperationException");
    let mut code: Vec<u8> = Vec::new();
    code.push(0xBB);
    code.extend_from_slice(&uoe_class.to_be_bytes());
    code.push(0x59);
    code.push(0xB7);
    code.extend_from_slice(&uoe_ctor.to_be_bytes());
    code.push(0xBF);
    (code, 2)
}

struct BuiltBody {
    code: Vec<u8>,
    max_stack: u16,
    max_locals: u16,
    sub_attrs: Vec<u8>,
    sub_attr_count: u16,
    exception_table: Vec<u8>,
    exception_count: u16,
    recovered: bool,
}

fn build_real_or_stub_body(
    dex: &DexFile,
    cp: &mut ConstantPool,
    method: &TranslatedMethod,
    code_item: Option<&CodeItem>,
) -> BuiltBody {
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    if let Some(item) = code_item {
        let emitted: Option<EmittedCode> = emit_method_code(dex, cp, item, is_static)
            .or_else(|| emit_branch_method_code(dex, cp, item, is_static));
        if let Some(emitted) = emitted {
            return BuiltBody {
                code: emitted.bytes,
                max_stack: emitted.max_stack,
                max_locals: emitted.max_locals,
                sub_attrs: emitted.attributes,
                sub_attr_count: emitted.attribute_count,
                exception_table: emitted.exception_table,
                exception_count: emitted.exception_count,
                recovered: true,
            };
        }
    }
    let (code, max_stack): (Vec<u8>, u16) = stub_code(cp);
    BuiltBody {
        code,
        max_stack,
        max_locals: method_local_slots(method),
        sub_attrs: Vec::new(),
        sub_attr_count: 0,
        exception_table: Vec::new(),
        exception_count: 0,
        recovered: false,
    }
}

fn build_method_attr(
    dex: &DexFile,
    cp: &mut ConstantPool,
    method: &TranslatedMethod,
    is_interface: bool,
    code_item: Option<&CodeItem>,
) -> (Vec<u8>, bool, bool) {
    let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
        && !(is_interface && method.access_flags & ACC_STATIC == 0);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&method.access_flags.to_be_bytes());
    out.extend_from_slice(&cp.utf8(&method.name).to_be_bytes());
    out.extend_from_slice(&cp.utf8(&method.descriptor).to_be_bytes());
    let mut recovered: bool = false;
    let mut stubbed: bool = false;
    if needs_code {
        let body: BuiltBody = build_real_or_stub_body(dex, cp, method, code_item);
        recovered = body.recovered;
        stubbed = !body.recovered;
        let code_attr_name: u16 = cp.utf8("Code");
        let mut code_attr: Vec<u8> = Vec::new();
        code_attr.extend_from_slice(&body.max_stack.to_be_bytes());
        code_attr.extend_from_slice(&body.max_locals.to_be_bytes());
        code_attr.extend_from_slice(&(body.code.len() as u32).to_be_bytes());
        code_attr.extend_from_slice(&body.code);
        code_attr.extend_from_slice(&body.exception_count.to_be_bytes());
        code_attr.extend_from_slice(&body.exception_table);
        code_attr.extend_from_slice(&body.sub_attr_count.to_be_bytes());
        code_attr.extend_from_slice(&body.sub_attrs);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&code_attr_name.to_be_bytes());
        out.extend_from_slice(&(code_attr.len() as u32).to_be_bytes());
        out.extend_from_slice(&code_attr);
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    let _ = descriptor_return_is_void;
    (out, recovered, stubbed)
}

fn method_local_slots(method: &TranslatedMethod) -> u16 {
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let mut slots: u16 = u16::from(!is_static);
    let inner: &str = method
        .descriptor
        .split_once('(')
        .and_then(|(_, rest): (&str, &str)| rest.split_once(')'))
        .map(|(p, _): (&str, &str)| p)
        .unwrap_or("");
    let bytes: &[u8] = inner.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1;
                slots += 1;
            }
            b'[' => {
                i += 1;
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                }
                i += 1;
                slots += 1;
            }
            b'J' | b'D' => {
                i += 1;
                slots += 2;
            }
            _ => {
                i += 1;
                slots += 1;
            }
        }
    }
    slots.max(1)
}

type MethodKey = (String, String);

fn write_class_file(
    dex: &DexFile,
    class: &TranslatedClass,
    code_items: &BTreeMap<MethodKey, CodeItem>,
) -> (Vec<u8>, usize, usize) {
    let mut cp: ConstantPool = ConstantPool::default();
    let this_class: u16 = cp.class(&class.internal_name);
    let super_class: u16 = cp.class(&class.super_name);
    let interface_indices: Vec<u16> = class
        .interfaces
        .iter()
        .map(|i: &String| cp.class(i))
        .collect();
    let is_interface: bool = class.is_interface();
    let mut field_section: Vec<u8> = Vec::new();
    field_section.extend_from_slice(&(class.fields.len() as u16).to_be_bytes());
    for field in &class.fields {
        field_section.extend_from_slice(&field.access_flags.to_be_bytes());
        field_section.extend_from_slice(&cp.utf8(&field.name).to_be_bytes());
        field_section.extend_from_slice(&cp.utf8(&field.descriptor).to_be_bytes());
        field_section.extend_from_slice(&0u16.to_be_bytes());
    }
    let mut method_section: Vec<u8> = Vec::new();
    method_section.extend_from_slice(&(class.methods.len() as u16).to_be_bytes());
    let mut recovered: usize = 0;
    let mut stubbed: usize = 0;
    for method in &class.methods {
        let key: MethodKey = (method.name.clone(), method.descriptor.clone());
        let code_item: Option<&CodeItem> = code_items.get(&key);
        let (attr, real, stub): (Vec<u8>, bool, bool) =
            build_method_attr(dex, &mut cp, method, is_interface, code_item);
        if real {
            recovered += 1;
        }
        if stub {
            stubbed += 1;
        }
        method_section.extend_from_slice(&attr);
    }

    let mut access: u16 = class.access_flags;
    if !is_interface {
        access |= ACC_SUPER;
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    out.extend_from_slice(&CLASS_VERSION_MINOR.to_be_bytes());
    out.extend_from_slice(&CLASS_VERSION_MAJOR.to_be_bytes());
    out.extend_from_slice(&cp.serialize());
    out.extend_from_slice(&access.to_be_bytes());
    out.extend_from_slice(&this_class.to_be_bytes());
    out.extend_from_slice(&super_class.to_be_bytes());
    out.extend_from_slice(&(interface_indices.len() as u16).to_be_bytes());
    for i in &interface_indices {
        out.extend_from_slice(&i.to_be_bytes());
    }
    out.extend_from_slice(&field_section);
    out.extend_from_slice(&method_section);
    out.extend_from_slice(&0u16.to_be_bytes());
    (out, recovered, stubbed)
}

fn code_items_by_class(items: Vec<CodeItem>) -> BTreeMap<String, BTreeMap<MethodKey, CodeItem>> {
    let mut out: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = BTreeMap::new();
    for item in items {
        let class_internal: String = dex_type_to_internal(&item.class);
        let key: MethodKey = (item.method_name.clone(), item.method_descriptor.clone());
        out.entry(class_internal).or_default().insert(key, item);
    }
    out
}

pub fn translate(dex: &DexFile, dex_bytes: &[u8]) -> Result<Dex2JarResult> {
    translate_with_limits(dex, dex_bytes, Dex2JarLimits::default())
}

pub fn translate_with_limits(
    dex: &DexFile,
    dex_bytes: &[u8],
    limits: Dex2JarLimits,
) -> Result<Dex2JarResult> {
    let declared: usize = usize::try_from(dex.header.class_defs_size).unwrap_or(usize::MAX);
    if declared > limits.classes {
        return Err(Error::Dex2JarLimit {
            kind: "class count",
            actual: declared,
            limit: limits.classes,
        });
    }
    let classes: Vec<TranslatedClass> = build_class_model(dex, dex_bytes);
    let code_report: crate::dex::CodeItemsReport = parse_code_items(dex, dex_bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> =
        code_items_by_class(code_report.into_partial_decoded());
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut jar_entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut method_total: usize = 0;
    let mut bodies_recovered: usize = 0;
    let mut stubbed_body_count: usize = 0;
    let mut class_bytes_total: usize = 0;
    for class in &classes {
        if jar_entries.len() >= limits.classes {
            return Err(Error::Dex2JarLimit {
                kind: "class count",
                actual: jar_entries.len().saturating_add(1),
                limit: limits.classes,
            });
        }
        method_total += class.methods.len();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        let (class_bytes, recovered, stubbed): (Vec<u8>, usize, usize) =
            write_class_file(dex, class, code_items);
        bodies_recovered += recovered;
        stubbed_body_count += stubbed;
        let path: String = format!("{}.class", class.internal_name);
        if jar_entries.contains_key(&path) {
            return Err(Error::DuplicateDex2JarPath(path));
        }
        let next: usize =
            class_bytes_total
                .checked_add(class_bytes.len())
                .ok_or(Error::Dex2JarLimit {
                    kind: "class bytes",
                    actual: usize::MAX,
                    limit: limits.class_bytes,
                })?;
        if next > limits.class_bytes {
            return Err(Error::Dex2JarLimit {
                kind: "class bytes",
                actual: next,
                limit: limits.class_bytes,
            });
        }
        class_bytes_total = next;
        jar_entries.insert(path, class_bytes);
    }
    Ok(Dex2JarResult {
        classes,
        jar_entries,
        method_total,
        bodies_recovered,
        stubbed_body_count,
        code_scan_complete,
        decode_error_count,
    })
}

pub fn assemble_jar(result: &Dex2JarResult) -> Result<Vec<u8>> {
    assemble_jar_with_limit(result, Dex2JarLimits::default().jar_bytes)
}

pub fn assemble_jar_with_limit(result: &Dex2JarResult, max_jar_bytes: usize) -> Result<Vec<u8>> {
    use zip::write::SimpleFileOptions;
    let writer = LimitedWriter {
        bytes: Vec::new(),
        limit: max_jar_bytes,
        position: 0,
        logical_len: 0,
        overflowed: false,
    };
    let mut zip: zip::ZipWriter<LimitedWriter> = zip::ZipWriter::new(writer);
    let opts: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("META-INF/MANIFEST.MF", opts)
        .map_err(|error| Error::Zip(error.to_string()))?;
    zip.write_all(b"Manifest-Version: 1.0\r\nCreated-By: disrobe dex2jar\r\n\r\n")?;
    for (name, data) in &result.jar_entries {
        zip.start_file(name.as_str(), opts)
            .map_err(|error| Error::Zip(error.to_string()))?;
        zip.write_all(data)?;
    }
    let writer: LimitedWriter = zip
        .finish()
        .map_err(|error| Error::Zip(error.to_string()))?;
    if writer.overflowed {
        return Err(Error::Dex2JarLimit {
            kind: "JAR bytes",
            actual: usize::try_from(writer.logical_len).unwrap_or(usize::MAX),
            limit: max_jar_bytes,
        });
    }
    Ok(writer.bytes)
}

pub fn translate_dex_bytes(dex_bytes: &[u8]) -> Result<Dex2JarResult> {
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    translate(&dex, dex_bytes)
}

#[cfg(any(test, feature = "lifter-diag"))]
pub fn diagnose_dex_bytes(dex_bytes: &[u8]) -> Result<BTreeMap<String, usize>> {
    use crate::dalvik::decode_method;
    use crate::dalvik_to_jvm::{
        emit_branch_method_code, emit_method_code, reset_bail_op, take_bail_kind, take_bail_op,
    };
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    let classes: Vec<TranslatedClass> = build_class_model(&dex, dex_bytes);
    let items: Vec<CodeItem> = parse_code_items(&dex, dex_bytes).into_complete()?;
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = code_items_by_class(items);
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
    for class in &classes {
        let is_interface: bool = class.is_interface();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        for method in &class.methods {
            let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
                && !(is_interface && method.access_flags & ACC_STATIC == 0);
            if !needs_code {
                continue;
            }
            let key: MethodKey = (method.name.clone(), method.descriptor.clone());
            let Some(item): Option<&CodeItem> = code_items.get(&key) else {
                *buckets.entry("no-code-item".to_string()).or_default() += 1;
                continue;
            };
            let is_static: bool = method.access_flags & ACC_STATIC != 0;
            let mut cp: ConstantPool = ConstantPool::default();
            reset_bail_op();
            let linear: Option<EmittedCode> = emit_method_code(&dex, &mut cp, item, is_static);
            if linear.is_some() {
                continue;
            }
            reset_bail_op();
            let branch: Option<EmittedCode> =
                emit_branch_method_code(&dex, &mut cp, item, is_static);
            if branch.is_some() {
                continue;
            }
            let width_conflict: bool =
                crate::dalvik_to_jvm::diag_has_width_conflict(&dex, item, is_static);
            let label: String = classify_stub(
                &dex,
                item,
                take_bail_op(),
                take_bail_kind(),
                width_conflict,
                &decode_method,
            );
            *buckets.entry(label).or_default() += 1;
        }
    }
    Ok(buckets)
}

#[cfg(any(test, feature = "lifter-diag"))]
pub fn diagnose_dex_methods(dex_bytes: &[u8]) -> Result<Vec<(String, String, String, String)>> {
    use crate::dalvik::decode_method;
    use crate::dalvik_to_jvm::{
        emit_branch_method_code, emit_method_code, reset_bail_op, take_bail_kind, take_bail_op,
    };
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    let classes: Vec<TranslatedClass> = build_class_model(&dex, dex_bytes);
    let items: Vec<CodeItem> = parse_code_items(&dex, dex_bytes).into_complete()?;
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = code_items_by_class(items);
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut out: Vec<(String, String, String, String)> = Vec::new();
    for class in &classes {
        let is_interface: bool = class.is_interface();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        for method in &class.methods {
            let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
                && !(is_interface && method.access_flags & ACC_STATIC == 0);
            if !needs_code {
                continue;
            }
            let key: MethodKey = (method.name.clone(), method.descriptor.clone());
            let Some(item): Option<&CodeItem> = code_items.get(&key) else {
                continue;
            };
            let is_static: bool = method.access_flags & ACC_STATIC != 0;
            let mut cp: ConstantPool = ConstantPool::default();
            reset_bail_op();
            if emit_method_code(&dex, &mut cp, item, is_static).is_some() {
                continue;
            }
            reset_bail_op();
            if emit_branch_method_code(&dex, &mut cp, item, is_static).is_some() {
                continue;
            }
            let branch_bail_op: i32 = take_bail_op();
            let branch_bail_kind: &str = take_bail_kind();
            let width_conflict: bool =
                crate::dalvik_to_jvm::diag_has_width_conflict(&dex, item, is_static);
            let label: String = classify_stub(
                &dex,
                item,
                branch_bail_op,
                branch_bail_kind,
                width_conflict,
                &decode_method,
            );
            let mnemonics: String = decode_method(&item.insns)
                .iter()
                .map(|i: &crate::dalvik::DalvikInsn| i.mnemonic)
                .collect::<Vec<&str>>()
                .join(" ");
            out.push((
                class.internal_name.clone(),
                method.name.clone(),
                format!("{label} | {mnemonics}"),
                method.descriptor.clone(),
            ));
        }
    }
    Ok(out)
}

#[cfg(any(test, feature = "lifter-diag"))]
fn classify_stub(
    dex: &DexFile,
    item: &CodeItem,
    bail_op: i32,
    bail_kind: &str,
    width_conflict: bool,
    decode: &dyn Fn(&[u16]) -> Vec<crate::dalvik::DalvikInsn>,
) -> String {
    use crate::dalvik::DalvikInsn;
    let insns: Vec<DalvikInsn> = decode(&item.insns);
    if insns.is_empty() {
        return "empty-or-undecodable".to_string();
    }
    if bail_op >= 0 {
        if !bail_kind.is_empty() {
            return format!("emit-bail-{bail_kind}");
        }
        return format!("emit-bail-op-{:#04x}", bail_op as u8);
    }
    if width_conflict {
        return "width-conflict".to_string();
    }
    if crate::dalvik_to_jvm::diag_is_synthetic_class(&item.class) {
        return "synthetic-class-rejected".to_string();
    }
    let has_branch: bool = insns.iter().any(|i: &DalvikInsn| {
        i.is_conditional_branch() || i.is_unconditional_goto() || i.is_switch()
    });
    let has_try: bool = !item.tries.is_empty();
    let is_init: bool = item.method_name == "<init>";
    if (has_branch || has_try) && is_init {
        return "init-ctor-gate".to_string();
    }
    if has_branch || has_try {
        if insns.iter().any(|i: &DalvikInsn| i.op == 0x26) {
            return "branch-gate-fill-array-data".to_string();
        }
        if has_try {
            return "branch-gate-try".to_string();
        }
        if insns.iter().any(|i: &DalvikInsn| i.op == 0x22) {
            return "branch-gate-new-instance".to_string();
        }
        if insns.iter().any(|i: &DalvikInsn| i.is_switch()) {
            return "branch-gate-switch".to_string();
        }
        return "branch-gate-typestate-or-stackmap".to_string();
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x22) {
        return "linear-new-instance".to_string();
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x0D) {
        return "linear-move-exception".to_string();
    }
    let last: usize = insns.len() - 1;
    if insns
        .iter()
        .take(last)
        .any(|i: &DalvikInsn| matches!(i.op, 0x0E..=0x11 | 0x27))
    {
        return "linear-early-return-or-throw".to_string();
    }
    let _ = dex;
    let dominant: u8 = insns.iter().map(|i: &DalvikInsn| i.op).max().unwrap_or(0);
    format!("linear-struct-max-op-{dominant:#04x}")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};

    #[test]
    fn dex_type_to_internal_strips_l_and_semicolon() {
        assert_eq!(dex_type_to_internal("LFoo/Bar;"), "Foo/Bar");
        assert_eq!(dex_type_to_internal("I"), "I");
    }

    #[test]
    fn local_slots_counts_long_double_as_two() {
        let m: TranslatedMethod = TranslatedMethod {
            name: "x".to_string(),
            descriptor: "(JD)V".to_string(),
            access_flags: ACC_STATIC,
            has_code: true,
        };
        assert_eq!(method_local_slots(&m), 4);
    }

    #[test]
    fn class_data_uleb128_rejects_values_wider_than_u32() {
        let overflow: [u8; 5] = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        assert_eq!(read_uleb128(&overflow, 0), None);
        assert_eq!(read_uleb128(&[0x80], 0), None);
    }

    #[test]
    fn translation_reports_incomplete_code_scan() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Invalid;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Invalid;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "body".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x0014],
                relocations: Vec::new(),
            }],
        });
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let result: Dex2JarResult = translate(&dex, &bytes).expect("translate");

        assert!(!result.code_scan_complete);
        assert_eq!(result.decode_error_count, 1);
        assert_eq!(result.bodies_recovered, 0);
        assert_eq!(result.stubbed_body_count, 1);
    }

    #[test]
    fn translation_limits_fail_with_typed_errors_before_output_is_materialized() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Limited;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let count = translate_with_limits(
            &dex,
            &bytes,
            Dex2JarLimits {
                classes: 0,
                class_bytes: 1,
                jar_bytes: 1,
            },
        )
        .expect_err("class count limit");
        assert!(matches!(
            count,
            Error::Dex2JarLimit {
                kind: "class count",
                ..
            }
        ));
        let bytes_limit = translate_with_limits(
            &dex,
            &bytes,
            Dex2JarLimits {
                classes: 1,
                class_bytes: 1,
                jar_bytes: 1,
            },
        )
        .expect_err("class byte limit");
        assert!(matches!(
            bytes_limit,
            Error::Dex2JarLimit {
                kind: "class bytes",
                ..
            }
        ));
    }

    #[test]
    fn duplicate_internal_class_paths_fail_before_map_insertion() {
        let mut builder: DexBuilder = DexBuilder::new();
        for _ in 0..2 {
            builder.add_class(ClassDef {
                class: "Lcom/disrobe/Duplicate;".to_owned(),
                super_class: "Ljava/lang/Object;".to_owned(),
                access_flags: 0x0001,
                static_fields: Vec::new(),
                static_values: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
            });
        }
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let error: Error = translate(&dex, &bytes).expect_err("duplicate class path");
        assert!(matches!(
            error,
            Error::DuplicateDex2JarPath(path) if path == "com/disrobe/Duplicate.class"
        ));
    }

    #[test]
    fn bounded_jar_assembly_refuses_a_tiny_limit() {
        let result = Dex2JarResult {
            classes: Vec::new(),
            jar_entries: BTreeMap::new(),
            method_total: 0,
            bodies_recovered: 0,
            stubbed_body_count: 0,
            code_scan_complete: true,
            decode_error_count: 0,
        };
        let error = assemble_jar_with_limit(&result, 1).expect_err("JAR limit");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "JAR bytes",
                ..
            }
        ));
    }
}
