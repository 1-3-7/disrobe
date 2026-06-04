use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const ABC_MINOR: u16 = 16;
pub const ABC_MAJOR: u16 = 46;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace {
    pub kind: u8,
    pub name_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSet {
    pub namespaces: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Multiname {
    QName { ns_index: u32, name_index: u32 },
    QNameA { ns_index: u32, name_index: u32 },
    RtqName { name_index: u32 },
    RtqNameA { name_index: u32 },
    RtqNameL,
    RtqNameLA,
    Multiname { name_index: u32, ns_set_index: u32 },
    MultinameA { name_index: u32, ns_set_index: u32 },
    MultinameL { ns_set_index: u32 },
    MultinameLA { ns_set_index: u32 },
    TypeName { base: u32, params: Vec<u32> },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstantPool {
    pub integers: Vec<i32>,
    pub uintegers: Vec<u32>,
    pub doubles: Vec<f64>,
    pub strings: Vec<String>,
    pub namespaces: Vec<Namespace>,
    pub ns_sets: Vec<NamespaceSet>,
    pub multinames: Vec<Multiname>,
}

impl ConstantPool {
    pub fn string_at(&self, idx: u32) -> Result<&str> {
        if idx == 0 {
            return Ok("*");
        }
        let i: usize = idx as usize;
        if i >= self.strings.len() {
            return Err(Error::AbcBadPoolIndex {
                pool: "strings",
                idx: i,
                size: self.strings.len(),
            });
        }
        Ok(self.strings[i].as_str())
    }

    pub fn namespace_name(&self, idx: u32) -> Result<&str> {
        if idx == 0 {
            return Ok("*");
        }
        let i: usize = idx as usize;
        if i >= self.namespaces.len() {
            return Err(Error::AbcBadPoolIndex {
                pool: "namespaces",
                idx: i,
                size: self.namespaces.len(),
            });
        }
        self.string_at(self.namespaces[i].name_index)
    }

    /// The namespace URI for rendering a `QName`, returning an empty string for
    /// the public namespace (name index 0) so a bare identifier is emitted
    /// rather than the `*::` any-namespace sentinel.
    pub fn namespace_uri(&self, idx: u32) -> Result<&str> {
        if idx == 0 {
            return Ok("");
        }
        let i: usize = idx as usize;
        if i >= self.namespaces.len() {
            return Err(Error::AbcBadPoolIndex {
                pool: "namespaces",
                idx: i,
                size: self.namespaces.len(),
            });
        }
        let name_index: u32 = self.namespaces[i].name_index;
        if name_index == 0 {
            return Ok("");
        }
        self.string_at(name_index)
    }

    pub fn multiname_at(&self, idx: u32) -> Result<&Multiname> {
        if idx == 0 {
            return Err(Error::AbcBadPoolIndex {
                pool: "multinames",
                idx: 0,
                size: self.multinames.len(),
            });
        }
        let i: usize = idx as usize;
        if i >= self.multinames.len() {
            return Err(Error::AbcBadPoolIndex {
                pool: "multinames",
                idx: i,
                size: self.multinames.len(),
            });
        }
        Ok(&self.multinames[i])
    }

    pub fn render_multiname(&self, idx: u32) -> Result<String> {
        if idx == 0 {
            return Ok("*".to_owned());
        }
        let mn: &Multiname = self.multiname_at(idx)?;
        let rendered: String = match mn {
            Multiname::QName {
                ns_index,
                name_index,
            }
            | Multiname::QNameA {
                ns_index,
                name_index,
            } => {
                let ns: &str = self.namespace_uri(*ns_index)?;
                let name: &str = self.string_at(*name_index)?;
                if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                }
            }
            Multiname::Multiname {
                name_index,
                ns_set_index: _,
            }
            | Multiname::MultinameA {
                name_index,
                ns_set_index: _,
            } => self.string_at(*name_index)?.to_owned(),
            Multiname::RtqName { name_index } | Multiname::RtqNameA { name_index } => {
                let name: &str = self.string_at(*name_index)?;
                format!("[ns]::{name}")
            }
            Multiname::RtqNameL | Multiname::RtqNameLA => "[ns]::[name]".to_owned(),
            Multiname::MultinameL { .. } | Multiname::MultinameLA { .. } => "[name]".to_owned(),
            Multiname::TypeName { base, params } => {
                let base_str: String = self.render_multiname(*base)?;
                let mut parts: Vec<String> = Vec::with_capacity(params.len());
                for p in params {
                    parts.push(self.render_multiname(*p)?);
                }
                format!("{}<{}>", base_str, parts.join(", "))
            }
        };
        Ok(rendered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodInfo {
    pub return_type: u32,
    pub param_types: Vec<u32>,
    pub name_index: u32,
    pub flags: u8,
    pub param_names: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionInfo {
    pub from: u32,
    pub to: u32,
    pub target: u32,
    pub exc_type: u32,
    pub var_name: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodBody {
    pub method: u32,
    pub max_stack: u32,
    pub local_count: u32,
    pub init_scope_depth: u32,
    pub max_scope_depth: u32,
    pub code: Vec<u8>,
    pub exceptions: Vec<ExceptionInfo>,
    pub traits: Vec<TraitInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraitInfo {
    pub name_index: u32,
    pub kind: u8,
    pub slot_id: u32,
    pub method_index: u32,
    pub type_name: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub name_index: u32,
    pub super_index: u32,
    pub flags: u8,
    pub protected_ns: u32,
    pub interfaces: Vec<u32>,
    pub iinit: u32,
    pub traits: Vec<TraitInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassInfo {
    pub cinit: u32,
    pub traits: Vec<TraitInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub init: u32,
    pub traits: Vec<TraitInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbcFile {
    pub minor: u16,
    pub major: u16,
    pub cpool: ConstantPool,
    pub methods: Vec<MethodInfo>,
    pub metadata_count: u32,
    pub instances: Vec<InstanceInfo>,
    pub classes: Vec<ClassInfo>,
    pub scripts: Vec<ScriptInfo>,
    pub method_bodies: Vec<MethodBody>,
}

impl AbcFile {
    #[must_use]
    pub fn class_names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.instances.len());
        for inst in &self.instances {
            match self.cpool.render_multiname(inst.name_index) {
                Ok(s) => out.push(s),
                Err(_) => out.push(format!("<bad-multiname#{}>", inst.name_index)),
            }
        }
        out
    }

    #[must_use]
    pub fn string_histogram(&self) -> BTreeMap<usize, usize> {
        let mut out: BTreeMap<usize, usize> = BTreeMap::new();
        for s in &self.cpool.strings {
            *out.entry(s.len()).or_insert(0) += 1;
        }
        out
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    fn bounded_count(&self, count: u32, min_entry_bytes: usize, pool: &'static str) -> Result<()> {
        let remaining: usize = self.remaining();
        let max_entries: usize = remaining / min_entry_bytes.max(1);
        if count as usize > max_entries.saturating_add(1) {
            return Err(Error::AbcPoolCountTooLarge {
                pool,
                count,
                remaining,
            });
        }
        Ok(())
    }

    #[inline]
    fn need(&self, n: usize) -> Result<()> {
        if self.pos.saturating_add(n) > self.bytes.len() {
            return Err(Error::AbcTruncated {
                offset: self.pos,
                needed: n,
                had: self.bytes.len().saturating_sub(self.pos),
            });
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v: u8 = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v: u16 = u16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn s24(&mut self) -> Result<i32> {
        self.need(3)?;
        let raw: u32 = u32::from(self.bytes[self.pos])
            | (u32::from(self.bytes[self.pos + 1]) << 8)
            | (u32::from(self.bytes[self.pos + 2]) << 16);
        self.pos += 3;
        let sign_extended: i32 = if (raw & 0x0080_0000) != 0 {
            (raw | 0xFF00_0000).cast_signed()
        } else {
            raw.cast_signed()
        };
        Ok(sign_extended)
    }

    fn u32_var(&mut self) -> Result<u32> {
        let mut acc: u32 = 0;
        let mut shift: u32 = 0;
        for i in 0..5 {
            let byte: u8 = self.u8()?;
            acc |= u32::from(byte & 0x7F) << shift;
            if (byte & 0x80) == 0 {
                return Ok(acc);
            }
            shift += 7;
            if i == 4 && (byte & 0xF0) != 0 {
                return Err(Error::AbcU30Overflow(acc));
            }
        }
        Ok(acc)
    }

    #[inline]
    fn u30(&mut self) -> Result<u32> {
        self.u32_var()
    }

    fn s32_var(&mut self) -> Result<i32> {
        Ok(self.u32_var()?.cast_signed())
    }

    fn f64_le(&mut self) -> Result<f64> {
        self.need(8)?;
        let mut buf: [u8; 8] = [0u8; 8];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(f64::from_le_bytes(buf))
    }

    fn string(&mut self, idx: usize) -> Result<String> {
        let len: usize = self.u30()? as usize;
        self.need(len)?;
        let bytes: &[u8] = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::AbcBadUtf8(idx))
    }
}

pub fn parse(bytes: &[u8]) -> Result<AbcFile> {
    let mut r: Reader<'_> = Reader::new(bytes);
    let minor: u16 = r.u16()?;
    let major: u16 = r.u16()?;
    if minor != ABC_MINOR || major != ABC_MAJOR {
        return Err(Error::BadAbcMagic { minor, major });
    }
    let cpool: ConstantPool = parse_constant_pool(&mut r)?;
    let method_count: u32 = r.u30()?;
    r.bounded_count(method_count, 3, "method")?;
    let mut methods: Vec<MethodInfo> = Vec::with_capacity(method_count as usize);
    for _ in 0..method_count {
        methods.push(parse_method_info(&mut r)?);
    }
    let metadata_count: u32 = r.u30()?;
    for _ in 0..metadata_count {
        let _name: u32 = r.u30()?;
        let item_count: u32 = r.u30()?;
        for _ in 0..item_count {
            let _k: u32 = r.u30()?;
            let _v: u32 = r.u30()?;
        }
    }
    let class_count: u32 = r.u30()?;
    r.bounded_count(class_count, 4, "class")?;
    let mut instances: Vec<InstanceInfo> = Vec::with_capacity(class_count as usize);
    for _ in 0..class_count {
        instances.push(parse_instance_info(&mut r)?);
    }
    let mut classes: Vec<ClassInfo> = Vec::with_capacity(class_count as usize);
    for _ in 0..class_count {
        classes.push(parse_class_info(&mut r)?);
    }
    let script_count: u32 = r.u30()?;
    r.bounded_count(script_count, 2, "script")?;
    let mut scripts: Vec<ScriptInfo> = Vec::with_capacity(script_count as usize);
    for _ in 0..script_count {
        scripts.push(parse_script_info(&mut r)?);
    }
    let body_count: u32 = r.u30()?;
    r.bounded_count(body_count, 6, "method_body")?;
    let mut method_bodies: Vec<MethodBody> = Vec::with_capacity(body_count as usize);
    for _ in 0..body_count {
        method_bodies.push(parse_method_body(&mut r)?);
    }
    Ok(AbcFile {
        minor,
        major,
        cpool,
        methods,
        metadata_count,
        instances,
        classes,
        scripts,
        method_bodies,
    })
}

fn parse_constant_pool(r: &mut Reader<'_>) -> Result<ConstantPool> {
    let mut cp: ConstantPool = ConstantPool::default();

    let int_count: u32 = r.u30()?;
    r.bounded_count(int_count, 1, "int")?;
    cp.integers = Vec::with_capacity(int_count.max(1) as usize);
    cp.integers.push(0);
    for _ in 1..int_count {
        cp.integers.push(r.s32_var()?);
    }

    let uint_count: u32 = r.u30()?;
    r.bounded_count(uint_count, 1, "uint")?;
    cp.uintegers = Vec::with_capacity(uint_count.max(1) as usize);
    cp.uintegers.push(0);
    for _ in 1..uint_count {
        cp.uintegers.push(r.u32_var()?);
    }

    let double_count: u32 = r.u30()?;
    r.bounded_count(double_count, 8, "double")?;
    cp.doubles = Vec::with_capacity(double_count.max(1) as usize);
    cp.doubles.push(f64::NAN);
    for _ in 1..double_count {
        cp.doubles.push(r.f64_le()?);
    }

    let string_count: u32 = r.u30()?;
    r.bounded_count(string_count, 1, "string")?;
    cp.strings = Vec::with_capacity(string_count.max(1) as usize);
    cp.strings.push(String::new());
    for i in 1..string_count {
        cp.strings.push(r.string(i as usize)?);
    }

    let ns_count: u32 = r.u30()?;
    r.bounded_count(ns_count, 2, "namespace")?;
    cp.namespaces = Vec::with_capacity(ns_count.max(1) as usize);
    cp.namespaces.push(Namespace {
        kind: 0,
        name_index: 0,
    });
    for _ in 1..ns_count {
        let kind: u8 = r.u8()?;
        let name_index: u32 = r.u30()?;
        cp.namespaces.push(Namespace { kind, name_index });
    }

    let ns_set_count: u32 = r.u30()?;
    r.bounded_count(ns_set_count, 1, "ns_set")?;
    cp.ns_sets = Vec::with_capacity(ns_set_count.max(1) as usize);
    cp.ns_sets.push(NamespaceSet {
        namespaces: Vec::new(),
    });
    for _ in 1..ns_set_count {
        let cnt: u32 = r.u30()?;
        r.bounded_count(cnt, 1, "ns_set_member")?;
        let mut ns: Vec<u32> = Vec::with_capacity(cnt as usize);
        for _ in 0..cnt {
            ns.push(r.u30()?);
        }
        cp.ns_sets.push(NamespaceSet { namespaces: ns });
    }

    let mn_count: u32 = r.u30()?;
    r.bounded_count(mn_count, 2, "multiname")?;
    cp.multinames = Vec::with_capacity(mn_count.max(1) as usize);
    cp.multinames.push(Multiname::QName {
        ns_index: 0,
        name_index: 0,
    });
    for i in 1..mn_count {
        cp.multinames.push(parse_multiname(r, i as usize)?);
    }

    Ok(cp)
}

fn parse_multiname(r: &mut Reader<'_>, idx: usize) -> Result<Multiname> {
    let kind: u8 = r.u8()?;
    let mn: Multiname = match kind {
        0x07 => Multiname::QName {
            ns_index: r.u30()?,
            name_index: r.u30()?,
        },
        0x0D => Multiname::QNameA {
            ns_index: r.u30()?,
            name_index: r.u30()?,
        },
        0x0F => Multiname::RtqName {
            name_index: r.u30()?,
        },
        0x10 => Multiname::RtqNameA {
            name_index: r.u30()?,
        },
        0x11 => Multiname::RtqNameL,
        0x12 => Multiname::RtqNameLA,
        0x09 => Multiname::Multiname {
            name_index: r.u30()?,
            ns_set_index: r.u30()?,
        },
        0x0E => Multiname::MultinameA {
            name_index: r.u30()?,
            ns_set_index: r.u30()?,
        },
        0x1B => Multiname::MultinameL {
            ns_set_index: r.u30()?,
        },
        0x1C => Multiname::MultinameLA {
            ns_set_index: r.u30()?,
        },
        0x1D => {
            let base: u32 = r.u30()?;
            let cnt: u32 = r.u30()?;
            r.bounded_count(cnt, 1, "typename_param")?;
            let mut params: Vec<u32> = Vec::with_capacity(cnt as usize);
            for _ in 0..cnt {
                params.push(r.u30()?);
            }
            Multiname::TypeName { base, params }
        }
        other => return Err(Error::AbcUnknownMultinameKind(other, idx)),
    };
    Ok(mn)
}

const METHOD_FLAG_HAS_OPTIONAL: u8 = 0x08;
const METHOD_FLAG_HAS_PARAM_NAMES: u8 = 0x80;

fn parse_method_info(r: &mut Reader<'_>) -> Result<MethodInfo> {
    let param_count: u32 = r.u30()?;
    let return_type: u32 = r.u30()?;
    r.bounded_count(param_count, 1, "method_param")?;
    let mut param_types: Vec<u32> = Vec::with_capacity(param_count as usize);
    for _ in 0..param_count {
        param_types.push(r.u30()?);
    }
    let name_index: u32 = r.u30()?;
    let flags: u8 = r.u8()?;
    if (flags & METHOD_FLAG_HAS_OPTIONAL) != 0 {
        let opt_count: u32 = r.u30()?;
        for _ in 0..opt_count {
            let _val: u32 = r.u30()?;
            let _kind: u8 = r.u8()?;
        }
    }
    let mut param_names: Vec<u32> = Vec::new();
    if (flags & METHOD_FLAG_HAS_PARAM_NAMES) != 0 {
        param_names.reserve_exact(param_count as usize);
        for _ in 0..param_count {
            param_names.push(r.u30()?);
        }
    }
    Ok(MethodInfo {
        return_type,
        param_types,
        name_index,
        flags,
        param_names,
    })
}

fn parse_trait(r: &mut Reader<'_>) -> Result<TraitInfo> {
    let name_index: u32 = r.u30()?;
    let kind_byte: u8 = r.u8()?;
    let kind: u8 = kind_byte & 0x0F;
    let (slot_id, method_index, type_name): (u32, u32, u32) = match kind {
        0 | 6 => {
            let slot_id: u32 = r.u30()?;
            let type_name: u32 = r.u30()?;
            let vindex: u32 = r.u30()?;
            if vindex != 0 {
                let _vkind: u8 = r.u8()?;
            }
            (slot_id, 0, type_name)
        }
        1..=5 => {
            let slot_id: u32 = r.u30()?;
            let method_index: u32 = r.u30()?;
            (slot_id, method_index, 0)
        }
        other => return Err(Error::AbcUnknownTraitKind(other, name_index)),
    };
    if (kind_byte & 0x40) != 0 {
        let metadata_count: u32 = r.u30()?;
        for _ in 0..metadata_count {
            let _m: u32 = r.u30()?;
        }
    }
    Ok(TraitInfo {
        name_index,
        kind: kind_byte,
        slot_id,
        method_index,
        type_name,
    })
}

const INSTANCE_FLAG_PROTECTED_NS: u8 = 0x08;

fn parse_instance_info(r: &mut Reader<'_>) -> Result<InstanceInfo> {
    let name_index: u32 = r.u30()?;
    let super_index: u32 = r.u30()?;
    let flags: u8 = r.u8()?;
    let protected_ns: u32 = if (flags & INSTANCE_FLAG_PROTECTED_NS) != 0 {
        r.u30()?
    } else {
        0
    };
    let intf_count: u32 = r.u30()?;
    r.bounded_count(intf_count, 1, "interface")?;
    let mut interfaces: Vec<u32> = Vec::with_capacity(intf_count as usize);
    for _ in 0..intf_count {
        interfaces.push(r.u30()?);
    }
    let iinit: u32 = r.u30()?;
    let trait_count: u32 = r.u30()?;
    r.bounded_count(trait_count, 2, "instance_trait")?;
    let mut traits: Vec<TraitInfo> = Vec::with_capacity(trait_count as usize);
    for _ in 0..trait_count {
        traits.push(parse_trait(r)?);
    }
    Ok(InstanceInfo {
        name_index,
        super_index,
        flags,
        protected_ns,
        interfaces,
        iinit,
        traits,
    })
}

fn parse_class_info(r: &mut Reader<'_>) -> Result<ClassInfo> {
    let cinit: u32 = r.u30()?;
    let trait_count: u32 = r.u30()?;
    r.bounded_count(trait_count, 2, "class_trait")?;
    let mut traits: Vec<TraitInfo> = Vec::with_capacity(trait_count as usize);
    for _ in 0..trait_count {
        traits.push(parse_trait(r)?);
    }
    Ok(ClassInfo { cinit, traits })
}

fn parse_script_info(r: &mut Reader<'_>) -> Result<ScriptInfo> {
    let init: u32 = r.u30()?;
    let trait_count: u32 = r.u30()?;
    r.bounded_count(trait_count, 2, "script_trait")?;
    let mut traits: Vec<TraitInfo> = Vec::with_capacity(trait_count as usize);
    for _ in 0..trait_count {
        traits.push(parse_trait(r)?);
    }
    Ok(ScriptInfo { init, traits })
}

fn parse_method_body(r: &mut Reader<'_>) -> Result<MethodBody> {
    let method: u32 = r.u30()?;
    let max_stack: u32 = r.u30()?;
    let local_count: u32 = r.u30()?;
    let init_scope_depth: u32 = r.u30()?;
    let max_scope_depth: u32 = r.u30()?;
    let code_len: u32 = r.u30()?;
    r.need(code_len as usize)
        .map_err(|_| Error::AbcBadCodeLen(code_len as usize))?;
    let code: Vec<u8> = r.bytes[r.pos..r.pos + code_len as usize].to_vec();
    r.pos += code_len as usize;
    let exc_count: u32 = r.u30()?;
    r.bounded_count(exc_count, 5, "exception")?;
    let mut exceptions: Vec<ExceptionInfo> = Vec::with_capacity(exc_count as usize);
    for _ in 0..exc_count {
        exceptions.push(ExceptionInfo {
            from: r.u30()?,
            to: r.u30()?,
            target: r.u30()?,
            exc_type: r.u30()?,
            var_name: r.u30()?,
        });
    }
    let trait_count: u32 = r.u30()?;
    r.bounded_count(trait_count, 2, "body_trait")?;
    let mut traits: Vec<TraitInfo> = Vec::with_capacity(trait_count as usize);
    for _ in 0..trait_count {
        traits.push(parse_trait(r)?);
    }
    Ok(MethodBody {
        method,
        max_stack,
        local_count,
        init_scope_depth,
        max_scope_depth,
        code,
        exceptions,
        traits,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmLine {
    pub offset: usize,
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub operands: Vec<i64>,
}

#[must_use]
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub fn opcode_mnemonic(op: u8) -> &'static str {
    match op {
        0x01 => "bkpt",
        0x02 => "nop",
        0x03 => "throw",
        0x04 => "getsuper",
        0x05 => "setsuper",
        0x06 => "dxns",
        0x07 => "dxnslate",
        0x08 => "kill",
        0x09 => "label",
        0x0C => "ifnlt",
        0x0D => "ifnle",
        0x0E => "ifngt",
        0x0F => "ifnge",
        0x10 => "jump",
        0x11 => "iftrue",
        0x12 => "iffalse",
        0x13 => "ifeq",
        0x14 => "ifne",
        0x15 => "iflt",
        0x16 => "ifle",
        0x17 => "ifgt",
        0x18 => "ifge",
        0x19 => "ifstricteq",
        0x1A => "ifstrictne",
        0x1B => "lookupswitch",
        0x1C => "pushwith",
        0x1D => "popscope",
        0x1E => "nextname",
        0x1F => "hasnext",
        0x20 => "pushnull",
        0x21 => "pushundefined",
        0x23 => "nextvalue",
        0x24 => "pushbyte",
        0x25 => "pushshort",
        0x26 => "pushtrue",
        0x27 => "pushfalse",
        0x28 => "pushnan",
        0x29 => "pop",
        0x2A => "dup",
        0x2B => "swap",
        0x2C => "pushstring",
        0x2D => "pushint",
        0x2E => "pushuint",
        0x2F => "pushdouble",
        0x30 => "pushscope",
        0x31 => "pushnamespace",
        0x32 => "hasnext2",
        0x40 => "newfunction",
        0x41 => "call",
        0x42 => "construct",
        0x43 => "callmethod",
        0x44 => "callstatic",
        0x45 => "callsuper",
        0x46 => "callproperty",
        0x47 => "returnvoid",
        0x48 => "returnvalue",
        0x49 => "constructsuper",
        0x4A => "constructprop",
        0x4C => "callproplex",
        0x4E => "callsupervoid",
        0x4F => "callpropvoid",
        0x53 => "applytype",
        0x55 => "newobject",
        0x56 => "newarray",
        0x57 => "newactivation",
        0x58 => "newclass",
        0x59 => "getdescendants",
        0x5A => "newcatch",
        0x5D => "findpropstrict",
        0x5E => "findproperty",
        0x60 => "getlex",
        0x61 => "setproperty",
        0x62 => "getlocal",
        0x63 => "setlocal",
        0x64 => "getglobalscope",
        0x65 => "getscopeobject",
        0x66 => "getproperty",
        0x68 => "initproperty",
        0x6A => "deleteproperty",
        0x6C => "getslot",
        0x6D => "setslot",
        0x70 => "convert_s",
        0x73 => "convert_i",
        0x74 => "convert_u",
        0x75 => "convert_d",
        0x76 => "convert_b",
        0x80 => "coerce",
        0x82 => "coerce_a",
        0x85 => "coerce_s",
        0x86 => "astype",
        0x87 => "astypelate",
        0x90 => "negate",
        0x91 => "increment",
        0x92 => "inclocal",
        0x93 => "decrement",
        0x94 => "declocal",
        0x95 => "typeof",
        0x96 => "not",
        0x97 => "bitnot",
        0xA0 => "add",
        0xA1 => "subtract",
        0xA2 => "multiply",
        0xA3 => "divide",
        0xA4 => "modulo",
        0xA5 => "lshift",
        0xA6 => "rshift",
        0xA7 => "urshift",
        0xA8 => "bitand",
        0xA9 => "bitor",
        0xAA => "bitxor",
        0xAB => "equals",
        0xAC => "strictequals",
        0xAD => "lessthan",
        0xAE => "lessequals",
        0xAF => "greaterthan",
        0xB0 => "greaterequals",
        0xB1 => "instanceof",
        0xB2 => "istype",
        0xB3 => "istypelate",
        0xB4 => "in",
        0xC0 => "increment_i",
        0xC1 => "decrement_i",
        0xC2 => "inclocal_i",
        0xC3 => "declocal_i",
        0xC4 => "negate_i",
        0xC5 => "add_i",
        0xC6 => "subtract_i",
        0xC7 => "multiply_i",
        0xD0 => "getlocal_0",
        0xD1 => "getlocal_1",
        0xD2 => "getlocal_2",
        0xD3 => "getlocal_3",
        0xD4 => "setlocal_0",
        0xD5 => "setlocal_1",
        0xD6 => "setlocal_2",
        0xD7 => "setlocal_3",
        0xEF => "debug",
        0xF0 => "debugline",
        0xF1 => "debugfile",
        _ => "<unknown>",
    }
}

#[must_use]
fn opcode_u30_operand_count(op: u8) -> u8 {
    match op {
        0x04 | 0x05 | 0x06 | 0x08 | 0x2C | 0x2D | 0x2E | 0x2F | 0x31 | 0x40 | 0x41 | 0x42
        | 0x49 | 0x53 | 0x55 | 0x56 | 0x58 | 0x59 | 0x5A | 0x5D | 0x5E | 0x60 | 0x61 | 0x62
        | 0x63 | 0x66 | 0x68 | 0x6A | 0x6C | 0x6D | 0x6E | 0x6F | 0x80 | 0x86 | 0x92 | 0x94
        | 0xB2 | 0xC2 | 0xC3 | 0xF0 | 0xF1 => 1,
        0x32 | 0x43 | 0x44 | 0x45 | 0x46 | 0x4A | 0x4C | 0x4E | 0x4F => 2,
        _ => 0,
    }
}

pub fn disasm(code: &[u8]) -> Result<Vec<DisasmLine>> {
    let mut r: Reader<'_> = Reader::new(code);
    let mut out: Vec<DisasmLine> = Vec::new();
    while r.pos < code.len() {
        let offset: usize = r.pos;
        let op: u8 = r.u8()?;
        let mnemonic: &'static str = opcode_mnemonic(op);
        let mut operands: Vec<i64> = Vec::new();
        match op {
            0x0C..=0x1A => {
                let target: i32 = r.s24()?;
                operands.push(i64::from(target));
            }
            0x24 => {
                let byte: u8 = r.u8()?;
                operands.push(i64::from(byte.cast_signed()));
            }
            0x65 => {
                let scope_index: u8 = r.u8()?;
                operands.push(i64::from(scope_index));
            }
            0x25 => {
                let short: i32 = r.s32_var()?;
                operands.push(i64::from(short));
            }
            0x1B => {
                let default_offset: i32 = r.s24()?;
                operands.push(i64::from(default_offset));
                let case_count: u32 = r.u30()?;
                operands.push(i64::from(case_count));
                for _ in 0..=case_count {
                    let case_target: i32 = r.s24()?;
                    operands.push(i64::from(case_target));
                }
            }
            0xEF => {
                operands.push(i64::from(r.u8()?));
                operands.push(i64::from(r.u30()?));
                operands.push(i64::from(r.u8()?));
                operands.push(i64::from(r.u30()?));
            }
            _ => {
                let n: u8 = opcode_u30_operand_count(op);
                for _ in 0..n {
                    operands.push(i64::from(r.u30()?));
                }
            }
        }
        out.push(DisasmLine {
            offset,
            opcode: op,
            mnemonic,
            operands,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn build_minimal_abc() -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&ABC_MINOR.to_le_bytes());
        b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
        b.push(0x01);
        b.push(0x01);
        b.push(0x01);
        b.push(0x01);
        b.push(0x01);
        b.push(0x01);
        b.push(0x01);
        b.push(0x00);
        b.push(0x00);
        b.push(0x00);
        b.push(0x00);
        b.push(0x00);
        b
    }

    #[test]
    fn rejects_bad_magic() {
        let bad: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        let err: Error = parse(&bad).expect_err("magic must fail");
        assert!(matches!(err, Error::BadAbcMagic { .. }));
    }

    #[test]
    fn parses_minimal_abc() {
        let bytes: Vec<u8> = build_minimal_abc();
        let abc: AbcFile = parse(&bytes).expect("minimal abc parse");
        assert_eq!(abc.minor, ABC_MINOR);
        assert_eq!(abc.major, ABC_MAJOR);
        assert_eq!(abc.cpool.strings.len(), 1);
        assert!(abc.methods.is_empty());
        assert!(abc.instances.is_empty());
    }

    #[test]
    fn disasm_basic_returnvoid() {
        let code: [u8; 2] = [0xD0, 0x47];
        let lines: Vec<DisasmLine> = disasm(&code).expect("disasm");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].mnemonic, "getlocal_0");
        assert_eq!(lines[1].mnemonic, "returnvoid");
    }

    #[test]
    fn malformed_varint_sixth_continuation_rejected() {
        let mut r: Reader<'_> = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let err: Error = r
            .u30()
            .expect_err("non-terminating 5-byte varint must reject");
        assert!(matches!(err, Error::AbcU30Overflow(_)));
    }

    #[test]
    fn full_u32_index_value_accepted() {
        let mut r: Reader<'_> = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        let v: u32 = r.u30().expect("full 32-bit varint must decode, not reject");
        assert_eq!(v, 0xFFFF_FFFF);
    }

    #[test]
    fn signed_int_constant_negative_one() {
        let mut r: Reader<'_> = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        let v: i32 = r.s32_var().expect("s32 -1 must decode");
        assert_eq!(v, -1);
    }

    #[test]
    fn signed_int_constant_positive_small() {
        let mut r: Reader<'_> = Reader::new(&[0x7F]);
        let v: i32 = r.s32_var().expect("s32 127 must decode");
        assert_eq!(v, 127);
    }

    #[test]
    fn uint_constant_full_range() {
        let mut r: Reader<'_> = Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x08]);
        let v: u32 = r.u32_var().expect("u32 high bit must decode");
        assert_eq!(v, 0x8000_0000);
    }
}
