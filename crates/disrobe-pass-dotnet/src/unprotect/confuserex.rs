use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{Instruction, MethodBody, OperandValue};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::PeImage;
use crate::peel::confuserex_constants::{ConstantsPool, mutate_id, recover_constants_pool};
use crate::signature::{TypeSig, TypeSigOrVoid};
use crate::tables::{MethodSpecRow, RowRef, TableId};

use super::body::{absolute_target, int_literal, nop_in_place, replace_in_place};
use super::{Literals, Residual};

pub(crate) const LAYER_CONSTANTS: &str = "ConfuserEx constants";
pub(crate) const LAYER_REF_PROXY: &str = "ConfuserEx reference proxy";
pub(crate) const LAYER_JUNK: &str = "ConfuserEx zero-length branches";

const MAX_SITES_PER_BODY: usize = 8192;
const MAX_POOL_STRING_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decoder {
    pub(crate) mul: u32,
    pub(crate) xor: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Shape {
    Text,
    Primitive,
}

#[derive(Debug, Default)]
pub(crate) struct TagLedger {
    tags: BTreeMap<(u32, Shape), BTreeSet<u32>>,
}

impl TagLedger {
    fn record(&mut self, decoder: u32, shape: Shape, tag: u32) {
        self.tags.entry((decoder, shape)).or_default().insert(tag);
    }

    #[must_use]
    pub(crate) fn inconsistency(&self) -> Option<String> {
        let mut seen: BTreeMap<(u32, u32), Shape> = BTreeMap::new();
        for ((decoder, shape), tags) in &self.tags {
            if tags.len() > 1 {
                return Some(format!(
                    "decoder {decoder:#x} decodes {shape:?} constants under {} different tag values {tags:?}",
                    tags.len()
                ));
            }
            for tag in tags {
                if let Some(other) = seen.insert((*decoder, *tag), *shape)
                    && other != *shape
                {
                    return Some(format!(
                        "decoder {decoder:#x} tag {tag} selects both {other:?} and {shape:?} constants"
                    ));
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Proxy {
    pub(crate) opcode_name: &'static str,
    pub(crate) target: u32,
}

#[derive(Debug)]
pub(crate) struct ConfuserExLayer {
    pub(crate) decoders: BTreeMap<u32, Decoder>,
    pub(crate) pool: Option<ConstantsPool>,
    pub(crate) pool_detail: String,
    pub(crate) proxies: BTreeMap<u32, Proxy>,
    pub(crate) ledger: TagLedger,
    pub(crate) runtime_methods: BTreeSet<u32>,
    pub(crate) constant_sites: u32,
    pub(crate) proxy_sites: u32,
    pub(crate) junk_branches: u32,
}

pub(crate) fn method_body(image: &[u8], pe: &PeImage, m: &MethodModel) -> Option<MethodBody> {
    if m.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(m.rva)?;
    crate::cil::parse_method_body(image.get(off..)?).ok()
}

const fn is_integral(sig: &TypeSig) -> bool {
    matches!(
        sig,
        TypeSig::I1
            | TypeSig::U1
            | TypeSig::I2
            | TypeSig::U2
            | TypeSig::I4
            | TypeSig::U4
            | TypeSig::I8
            | TypeSig::U8
            | TypeSig::Char
    )
}

fn decoder_mutation(body: &MethodBody) -> Option<Decoder> {
    let instrs: &[Instruction] = &body.instructions;
    for window in instrs.windows(6) {
        let [load, mul_lit, mul, xor_lit, xor, store] = window else {
            continue;
        };
        if load.name == "ldarg.0"
            && mul.name == "mul"
            && xor.name == "xor"
            && matches!(store.name.as_str(), "starg.s" | "starg")
            && let Some(m) = int_literal(mul_lit)
            && let Some(x) = int_literal(xor_lit)
        {
            return Some(Decoder {
                mul: (m as u64 & 0xFFFF_FFFF) as u32,
                xor: (x as u64 & 0xFFFF_FFFF) as u32,
            });
        }
    }
    None
}

fn is_decoder_shape(m: &MethodModel) -> bool {
    m.is_static()
        && m.signature.generic_param_count == 1
        && m.signature.params.len() == 1
        && is_integral(&m.signature.params[0])
        && matches!(
            m.signature.return_type,
            TypeSigOrVoid::Type(TypeSig::MVar(0))
        )
}

fn proxy_shape(body: &MethodBody, m: &MethodModel) -> Option<Proxy> {
    let instrs: Vec<&Instruction> = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| i.name != "nop")
        .collect();
    let arity: usize = m.signature.params.len();
    if instrs.len() != arity + 2 || !m.is_static() {
        return None;
    }
    for (index, ins) in instrs.iter().take(arity).enumerate() {
        let slot: Option<u16> = crate::cil::slot_index_of(ins, crate::cil::SlotOp::LoadArgument);
        if slot != u16::try_from(index).ok() {
            return None;
        }
    }
    let call: &Instruction = instrs.get(arity)?;
    let OperandValue::Token(target) = call.operand else {
        return None;
    };
    let opcode_name: &'static str = match call.name.as_str() {
        "call" => "call",
        "callvirt" => "callvirt",
        "newobj" => "newobj",
        _ => return None,
    };
    if instrs.get(arity + 1)?.name != "ret" {
        return None;
    }
    Some(Proxy {
        opcode_name,
        target,
    })
}

impl ConfuserExLayer {
    pub(crate) fn build(
        image: &[u8],
        pe: &PeImage,
        resolver: &Resolver,
        model: &AssemblyModel,
    ) -> Self {
        let mut decoders: BTreeMap<u32, Decoder> = BTreeMap::new();
        let mut proxies: BTreeMap<u32, Proxy> = BTreeMap::new();
        let mut runtime_methods: BTreeSet<u32> = BTreeSet::new();
        for ty in &model.types {
            let is_module: bool = ty.full_name == "<Module>";
            for m in &ty.methods {
                let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
                    continue;
                };
                if is_decoder_shape(m)
                    && let Some(decoder) = decoder_mutation(&body)
                {
                    decoders.insert(m.token, decoder);
                    runtime_methods.insert(m.token);
                    continue;
                }
                if is_module {
                    runtime_methods.insert(m.token);
                    continue;
                }
                if let Some(proxy) = proxy_shape(&body, m)
                    && resolver.callee_signature(proxy.target).is_some()
                {
                    proxies.insert(m.token, proxy);
                }
            }
        }
        let mut pool: Option<ConstantsPool> = if decoders.is_empty() {
            None
        } else {
            recover_constants_pool(image).ok().flatten()
        };
        let mut pool_detail: String = String::from("pool decrypted from the xorshift seed");
        if pool.is_none() && !decoders.is_empty() {
            match emulated_pool(image, pe, resolver, model, &decoders) {
                Ok(recovered) => {
                    pool_detail = recovered.1;
                    pool = Some(recovered.0);
                }
                Err(reason) => pool_detail = reason,
            }
        }
        Self {
            decoders,
            pool,
            pool_detail,
            proxies,
            ledger: TagLedger::default(),
            runtime_methods,
            constant_sites: 0,
            proxy_sites: 0,
            junk_branches: 0,
        }
    }

    #[must_use]
    pub(crate) fn present(&self) -> bool {
        !self.decoders.is_empty() || !self.proxies.is_empty()
    }

    fn decoder_for_call(&self, resolver: &Resolver, token: u32) -> Option<(u32, Decoder)> {
        let table: TableId = TableId::from_index(u8::try_from(token >> 24).ok()?)?;
        let def: u32 = match table {
            TableId::MethodDef => token,
            TableId::MethodSpec => {
                let rid: usize = usize::try_from(token & 0x00FF_FFFF).ok()?.checked_sub(1)?;
                let row: &MethodSpecRow = resolver.tables().method_specs.get(rid)?;
                let method: RowRef = row.method?;
                (method.table == TableId::MethodDef).then_some(0x0600_0000 | method.row)?
            }
            _ => return None,
        };
        self.decoders.get(&def).map(|d: &Decoder| (def, *d))
    }

    pub(crate) fn rewrite(
        &mut self,
        method_token: u32,
        body: &mut MethodBody,
        resolver: &Resolver,
        literals: &mut Literals,
        residuals: &mut Vec<Residual>,
    ) -> bool {
        let mut changed: bool = false;
        changed |= self.nop_zero_length_branches(body);
        changed |= self.inline_proxies(body);
        changed |= self.inline_constants(method_token, body, resolver, literals, residuals);
        changed
    }

    fn nop_zero_length_branches(&mut self, body: &mut MethodBody) -> bool {
        let mut hits: Vec<usize> = Vec::new();
        for index in 0..body.instructions.len() {
            let ins: &Instruction = &body.instructions[index];
            if !matches!(ins.name.as_str(), "br" | "br.s") {
                continue;
            }
            let next: Option<u32> = body
                .instructions
                .get(index + 1)
                .map(|n: &Instruction| n.offset);
            if absolute_target(body, index).is_some() && absolute_target(body, index) == next {
                hits.push(index);
            }
        }
        for index in &hits {
            nop_in_place(&mut body.instructions[*index]);
        }
        self.junk_branches = self
            .junk_branches
            .saturating_add(u32::try_from(hits.len()).unwrap_or(u32::MAX));
        !hits.is_empty()
    }

    fn inline_proxies(&mut self, body: &mut MethodBody) -> bool {
        if self.proxies.is_empty() {
            return false;
        }
        let mut changed: bool = false;
        for ins in &mut body.instructions {
            if ins.name != "call" {
                continue;
            }
            let OperandValue::Token(token) = ins.operand else {
                continue;
            };
            let Some(proxy): Option<Proxy> = self.proxies.get(&token).copied() else {
                continue;
            };
            if replace_in_place(ins, proxy.opcode_name, OperandValue::Token(proxy.target)) {
                self.proxy_sites = self.proxy_sites.saturating_add(1);
                changed = true;
            }
        }
        changed
    }

    fn inline_constants(
        &mut self,
        method_token: u32,
        body: &mut MethodBody,
        resolver: &Resolver,
        literals: &mut Literals,
        residuals: &mut Vec<Residual>,
    ) -> bool {
        if self.decoders.is_empty() {
            return false;
        }
        let mut changed: bool = false;
        let mut sites: usize = 0;
        let mut index: usize = 0;
        while index < body.instructions.len() {
            let call_index: usize = index;
            index += 1;
            let ins: &Instruction = &body.instructions[call_index];
            if ins.name != "call" {
                continue;
            }
            let OperandValue::Token(token) = ins.operand else {
                continue;
            };
            let Some((def, decoder)): Option<(u32, Decoder)> =
                self.decoder_for_call(resolver, token)
            else {
                continue;
            };
            sites += 1;
            if sites > MAX_SITES_PER_BODY {
                residuals.push(Residual {
                    layer: LAYER_CONSTANTS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "more than {MAX_SITES_PER_BODY} decoder call sites in one body"
                    ),
                });
                return changed;
            }
            let Some(pool): Option<&ConstantsPool> = self.pool.as_ref() else {
                residuals.push(Residual {
                    layer: LAYER_CONSTANTS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "the constants pool could not be recovered ({}), so decoder calls stay",
                        self.pool_detail
                    ),
                });
                return changed;
            };
            let Some(id_index): Option<usize> = argument_literal_index(body, call_index) else {
                residuals.push(Residual {
                    layer: LAYER_CONSTANTS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "decoder call at offset {:#x} does not take a literal argument",
                        body.instructions[call_index].offset
                    ),
                });
                continue;
            };
            let Some(id): Option<i64> = int_literal(&body.instructions[id_index]) else {
                continue;
            };
            let id: u32 = (id as u64 & 0xFFFF_FFFF) as u32;
            let Some(TypeSigOrVoid::Type(ret)): Option<TypeSigOrVoid> =
                resolver.callee_instantiated_return(token)
            else {
                residuals.push(Residual {
                    layer: LAYER_CONSTANTS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "decoder call at offset {:#x} has no concrete instantiation",
                        body.instructions[call_index].offset
                    ),
                });
                continue;
            };
            let (tag, offset): (u32, u32) = mutate_id(id, decoder.mul, decoder.xor);
            match decode(&pool.pool, offset, &ret) {
                Ok((shape, literal)) => {
                    self.ledger.record(def, shape, tag);
                    let replaced: bool = match literal {
                        Literal::Text(units) => {
                            let Some(synthetic): Option<u32> = literals.intern(units) else {
                                residuals.push(Residual {
                                    layer: LAYER_CONSTANTS.to_owned(),
                                    method_token: Some(method_token),
                                    reason: "the synthetic string table is full".to_owned(),
                                });
                                continue;
                            };
                            replace_in_place(
                                &mut body.instructions[call_index],
                                "ldstr",
                                OperandValue::Token(synthetic),
                            )
                        }
                        Literal::I4(v) => replace_in_place(
                            &mut body.instructions[call_index],
                            "ldc.i4",
                            OperandValue::I32(v),
                        ),
                        Literal::I8(v) => replace_in_place(
                            &mut body.instructions[call_index],
                            "ldc.i8",
                            OperandValue::I64(v),
                        ),
                        Literal::R4(bits) => replace_in_place(
                            &mut body.instructions[call_index],
                            "ldc.r4",
                            OperandValue::F32Bits(bits),
                        ),
                        Literal::R8(bits) => replace_in_place(
                            &mut body.instructions[call_index],
                            "ldc.r8",
                            OperandValue::F64Bits(bits),
                        ),
                    };
                    if replaced {
                        for between in id_index..call_index {
                            nop_in_place(&mut body.instructions[between]);
                        }
                        self.constant_sites = self.constant_sites.saturating_add(1);
                        changed = true;
                    }
                }
                Err(reason) => residuals.push(Residual {
                    layer: LAYER_CONSTANTS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "decoder call at offset {:#x}: {reason}",
                        body.instructions[call_index].offset
                    ),
                }),
            }
        }
        changed
    }
}

fn argument_literal_index(body: &MethodBody, call_index: usize) -> Option<usize> {
    let mut cursor: usize = call_index;
    while cursor > 0 {
        cursor -= 1;
        let ins: &Instruction = &body.instructions[cursor];
        if ins.name == "nop" {
            continue;
        }
        if matches!(ins.name.as_str(), "br" | "br.s") {
            let next: Option<u32> = body
                .instructions
                .get(cursor + 1)
                .map(|n: &Instruction| n.offset);
            if absolute_target(body, cursor) == next {
                continue;
            }
            return None;
        }
        return int_literal(ins).map(|_| cursor);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Literal {
    Text(Vec<u16>),
    I4(i32),
    I8(i64),
    R4(u32),
    R8(u64),
}

fn read_le(pool: &[u8], offset: usize, width: usize) -> Result<u64, String> {
    let end: usize = offset
        .checked_add(width)
        .ok_or_else(|| "constant offset overflows".to_owned())?;
    let bytes: &[u8] = pool.get(offset..end).ok_or_else(|| {
        format!(
            "constant offset {offset:#x} lies outside the {}-byte pool",
            pool.len()
        )
    })?;
    let mut value: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        value |= u64::from(*b) << (8 * i);
    }
    Ok(value)
}

fn decode(pool: &[u8], offset: u32, ret: &TypeSig) -> Result<(Shape, Literal), String> {
    let off: usize = usize::try_from(offset).map_err(|_| "constant offset overflows".to_owned())?;
    match ret {
        TypeSig::String => {
            let count: usize = usize::try_from(read_le(pool, off, 4)?)
                .map_err(|_| "string length overflows".to_owned())?;
            if count > MAX_POOL_STRING_BYTES {
                return Err(format!(
                    "string length {count} exceeds the {MAX_POOL_STRING_BYTES}-byte bound"
                ));
            }
            let start: usize = off + 4;
            let end: usize = start
                .checked_add(count)
                .ok_or_else(|| "string end overflows".to_owned())?;
            let bytes: &[u8] = pool.get(start..end).ok_or_else(|| {
                format!("string of {count} bytes at {start:#x} lies outside the pool")
            })?;
            let text: &str = core::str::from_utf8(bytes)
                .map_err(|_| format!("string at {start:#x} is not UTF-8"))?;
            Ok((Shape::Text, Literal::Text(text.encode_utf16().collect())))
        }
        TypeSig::Boolean | TypeSig::U1 => {
            Ok((Shape::Primitive, Literal::I4(read_le(pool, off, 1)? as i32)))
        }
        TypeSig::I1 => Ok((
            Shape::Primitive,
            Literal::I4(i32::from((read_le(pool, off, 1)? as u8).cast_signed())),
        )),
        TypeSig::Char | TypeSig::U2 => {
            Ok((Shape::Primitive, Literal::I4(read_le(pool, off, 2)? as i32)))
        }
        TypeSig::I2 => Ok((
            Shape::Primitive,
            Literal::I4(i32::from((read_le(pool, off, 2)? as u16).cast_signed())),
        )),
        TypeSig::I4 | TypeSig::U4 => Ok((
            Shape::Primitive,
            Literal::I4((read_le(pool, off, 4)? as u32).cast_signed()),
        )),
        TypeSig::I8 | TypeSig::U8 => Ok((
            Shape::Primitive,
            Literal::I8(read_le(pool, off, 8)?.cast_signed()),
        )),
        TypeSig::R4 => Ok((Shape::Primitive, Literal::R4(read_le(pool, off, 4)? as u32))),
        TypeSig::R8 => Ok((Shape::Primitive, Literal::R8(read_le(pool, off, 8)?))),
        TypeSig::SzArray(_) => Err("array initializers are not inlined".to_owned()),
        other => Err(format!("unsupported constant type {}", other.render())),
    }
}

const MAX_EMULATED_POOL_BYTES: usize = 64 * 1024 * 1024;

fn pool_field_of(
    image: &[u8],
    pe: &PeImage,
    model: &AssemblyModel,
    decoders: &BTreeMap<u32, Decoder>,
) -> Option<u32> {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for ty in &model.types {
        for m in &ty.methods {
            if !decoders.contains_key(&m.token) {
                continue;
            }
            let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
                continue;
            };
            for ins in &body.instructions {
                if ins.name == "ldsfld"
                    && let OperandValue::Token(t) = ins.operand
                    && t >> 24 == 0x04
                {
                    *counts.entry(t).or_insert(0) += 1;
                }
            }
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, count): &(u32, usize)| *count)
        .map(|(token, _): (u32, usize)| token)
}

fn is_bytes_to_bytes(m: &MethodModel) -> bool {
    m.is_static()
        && matches!(m.signature.params.as_slice(), [TypeSig::SzArray(inner)] if matches!(inner.as_ref(), TypeSig::U1))
        && matches!(&m.signature.return_type, TypeSigOrVoid::Type(TypeSig::SzArray(inner)) if matches!(inner.as_ref(), TypeSig::U1))
}

fn emulated_pool(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    model: &AssemblyModel,
    decoders: &BTreeMap<u32, Decoder>,
) -> Result<(ConstantsPool, String), String> {
    let pool_field: u32 = pool_field_of(image, pe, model, decoders)
        .ok_or_else(|| "no decoder reads a static pool field".to_owned())?;
    let module: &TypeModel = module_type(model).ok_or_else(|| "no <Module> type".to_owned())?;
    let decompressors: Vec<u32> = module
        .methods
        .iter()
        .filter(|m: &&MethodModel| is_bytes_to_bytes(m))
        .map(|m: &MethodModel| m.token)
        .collect();
    if decompressors.is_empty() {
        return Err("no byte[] -> byte[] decompressor in <Module>".to_owned());
    }
    let clr: crate::pe::ClrHeader =
        crate::pe::parse_clr_header(image, pe).map_err(|e| e.to_string())?;
    let root: crate::metadata::MetadataRoot =
        crate::metadata::parse_metadata_root(image, pe, &clr).map_err(|e| e.to_string())?;
    let metadata: &[u8] =
        crate::metadata::metadata_slice(image, pe, &clr, &root).map_err(|e| e.to_string())?;
    let blob: &[u8] = root
        .streams
        .get("#Blob")
        .and_then(|h: &crate::metadata::StreamHeader| {
            let start: usize = usize::try_from(h.offset).ok()?;
            let end: usize = start.checked_add(usize::try_from(h.size).ok()?)?;
            metadata.get(start..end)
        })
        .unwrap_or(&[]);
    let env: crate::cil_emulator::FieldInitEnv =
        crate::peel::deflatten::decrypt::initializer_env(image, pe, resolver, model, blob);
    let mut last_error: String =
        "no <Module> method stores the pool field after calling the decompressor".to_owned();
    for m in &module.methods {
        let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
            continue;
        };
        let stores_pool: bool = body.instructions.iter().any(|i: &Instruction| {
            i.name == "stsfld" && i.operand == OperandValue::Token(pool_field)
        });
        let Some(decompressor): Option<u32> =
            body.instructions
                .iter()
                .find_map(|i: &Instruction| match i.operand {
                    OperandValue::Token(t) if i.name == "call" && decompressors.contains(&t) => {
                        Some(t)
                    }
                    _ => None,
                })
        else {
            continue;
        };
        if !stores_pool {
            continue;
        }
        match crate::cil_emulator::emulate_until_call(&body, &env, decompressor, 1) {
            Ok(arrays) => {
                let Some(compressed): Option<&Vec<u8>> = arrays.first() else {
                    last_error = format!(
                        "initializer {:#x} reached the decompressor without a byte array",
                        m.token
                    );
                    continue;
                };
                if compressed.len() > MAX_EMULATED_POOL_BYTES {
                    last_error = format!(
                        "initializer {:#x} produced {} compressed bytes, above the bound",
                        m.token,
                        compressed.len()
                    );
                    continue;
                }
                let decompressed: Result<Vec<u8>, crate::error::Error> =
                    crate::peel::confuserex_resources::lzma_decompress(compressed).or_else(|_| {
                        crate::peel::confuserex_resources::lzma_decompress_standard(compressed)
                    });
                match decompressed {
                    Ok(pool) if !pool.is_empty() => {
                        let mut hasher: sha2::Sha256 = <sha2::Sha256 as sha2::Digest>::new();
                        sha2::Digest::update(&mut hasher, compressed);
                        let digest = sha2::Digest::finalize(hasher);
                        let mut blob_sha256: [u8; 32] = [0u8; 32];
                        blob_sha256.copy_from_slice(digest.as_slice());
                        return Ok((
                            ConstantsPool {
                                seed: 0,
                                blob_rva: 0,
                                blob_size: u32::try_from(compressed.len()).unwrap_or(u32::MAX),
                                blob_sha256,
                                seeds_tried: Vec::new(),
                                pool,
                            },
                            format!(
                                "pool recovered by emulating initializer {:#x} up to its LZMA decompressor call",
                                m.token
                            ),
                        ));
                    }
                    Ok(_) => {
                        last_error =
                            format!("initializer {:#x} decompressed to an empty pool", m.token)
                    }
                    Err(e) => {
                        last_error = format!(
                            "initializer {:#x}: the captured buffer is not an LZMA stream ({e})",
                            m.token
                        )
                    }
                }
            }
            Err(e) => {
                last_error = format!(
                    "initializer {:#x} did not emulate to the decompressor call: {e:?}",
                    m.token
                )
            }
        }
    }
    Err(last_error)
}

#[must_use]
pub(crate) fn module_type(model: &AssemblyModel) -> Option<&TypeModel> {
    model
        .types
        .iter()
        .find(|t: &&TypeModel| t.full_name == "<Module>")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn string_decoding_reads_the_count_prefix() {
        let mut pool: Vec<u8> = Vec::new();
        pool.extend_from_slice(&5u32.to_le_bytes());
        pool.extend_from_slice(b"hello");
        let (shape, literal): (Shape, Literal) = decode(&pool, 0, &TypeSig::String).unwrap();
        assert_eq!(shape, Shape::Text);
        assert_eq!(literal, Literal::Text("hello".encode_utf16().collect()));
    }

    #[test]
    fn primitive_decoding_sign_extends_narrow_types() {
        let pool: Vec<u8> = vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&pool, 0, &TypeSig::I1).unwrap().1, Literal::I4(-1));
        assert_eq!(decode(&pool, 0, &TypeSig::U1).unwrap().1, Literal::I4(255));
        assert_eq!(decode(&pool, 0, &TypeSig::I2).unwrap().1, Literal::I4(-1));
        assert_eq!(
            decode(&pool, 0, &TypeSig::U4).unwrap().1,
            Literal::I4(65535)
        );
        assert_eq!(
            decode(&pool, 0, &TypeSig::I8).unwrap().1,
            Literal::I8(65535)
        );
    }

    #[test]
    fn decoding_outside_the_pool_is_a_typed_refusal() {
        let pool: Vec<u8> = vec![9, 0, 0, 0, b'a'];
        assert!(decode(&pool, 0, &TypeSig::String).is_err());
        assert!(decode(&pool, 0x10, &TypeSig::I4).is_err());
        assert!(decode(&pool, u32::MAX, &TypeSig::I4).is_err());
        assert!(decode(&pool, 0, &TypeSig::SzArray(Box::new(TypeSig::U1))).is_err());
    }

    #[test]
    fn ledger_flags_a_tag_shared_by_two_shapes() {
        let mut ledger: TagLedger = TagLedger::default();
        ledger.record(0x0600_0004, Shape::Text, 0);
        ledger.record(0x0600_0004, Shape::Primitive, 2);
        ledger.record(0x0600_0005, Shape::Text, 2);
        assert!(ledger.inconsistency().is_none());
        ledger.record(0x0600_0004, Shape::Primitive, 0);
        assert!(ledger.inconsistency().is_some());
    }
}
