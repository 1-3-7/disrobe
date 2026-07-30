use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedValue {
    String(String),
    Int(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub class: String,
    pub type_desc: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoRef {
    pub return_type: String,
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRef {
    pub class: String,
    pub proto: ProtoRef,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Reloc {
    StringIndex { unit: usize, value: String },
    TypeIndex { unit: usize, descriptor: String },
    FieldIndex { unit: usize, field: FieldRef },
    MethodIndex { unit: usize, method: MethodRef },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMethod {
    pub method: MethodRef,
    pub access_flags: u32,
    pub is_direct: bool,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<u16>,
    pub relocations: Vec<Reloc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedField {
    pub field: FieldRef,
    pub access_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    pub class: String,
    pub super_class: String,
    pub access_flags: u32,
    pub static_fields: Vec<EncodedField>,
    pub static_values: Vec<EncodedValue>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone, Default)]
pub struct DexBuilder {
    classes: Vec<ClassDef>,
    extra_strings: Vec<String>,
}

impl DexBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern_string(&mut self, value: &str) {
        self.extra_strings.push(value.to_owned());
    }

    pub fn add_class(&mut self, def: ClassDef) {
        self.classes.push(def);
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut pool: StringPool = StringPool::new();
        for class in &self.classes {
            pool.intern(&class.class);
            pool.intern(&class.super_class);
            for field in &class.static_fields {
                pool.intern(&field.field.class);
                pool.intern(&field.field.type_desc);
                pool.intern(&field.field.name);
            }
            for value in &class.static_values {
                if let EncodedValue::String(content) = value {
                    pool.intern(content);
                }
            }
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                pool.intern(&method.method.class);
                pool.intern(&method.method.name);
                pool.intern(&method.method.proto.return_type);
                for p in &method.method.proto.params {
                    pool.intern(p);
                }
                for reloc in &method.relocations {
                    match reloc {
                        Reloc::StringIndex { value, .. } => pool.intern(value),
                        Reloc::TypeIndex { descriptor, .. } => pool.intern(descriptor),
                        Reloc::FieldIndex { field, .. } => {
                            pool.intern(&field.class);
                            pool.intern(&field.type_desc);
                            pool.intern(&field.name);
                        }
                        Reloc::MethodIndex { method: m, .. } => {
                            pool.intern(&m.class);
                            pool.intern(&m.name);
                            pool.intern(&m.proto.return_type);
                            for p in &m.proto.params {
                                pool.intern(p);
                            }
                        }
                    }
                }
            }
        }
        for s in &self.extra_strings {
            pool.intern(s);
        }
        pool.finalize_order();

        let mut types: TypePool = TypePool::new();
        for class in &self.classes {
            types.intern(&pool, &class.class);
            types.intern(&pool, &class.super_class);
            for field in &class.static_fields {
                types.intern(&pool, &field.field.class);
                types.intern(&pool, &field.field.type_desc);
            }
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                types.intern(&pool, &method.method.class);
                types.intern(&pool, &method.method.proto.return_type);
                for p in &method.method.proto.params {
                    types.intern(&pool, p);
                }
                for reloc in &method.relocations {
                    match reloc {
                        Reloc::TypeIndex { descriptor, .. } => types.intern(&pool, descriptor),
                        Reloc::FieldIndex { field, .. } => {
                            types.intern(&pool, &field.class);
                            types.intern(&pool, &field.type_desc);
                        }
                        Reloc::MethodIndex { method: m, .. } => {
                            types.intern(&pool, &m.class);
                            types.intern(&pool, &m.proto.return_type);
                            for p in &m.proto.params {
                                types.intern(&pool, p);
                            }
                        }
                        Reloc::StringIndex { .. } => {}
                    }
                }
            }
        }
        types.finalize();

        let mut protos: ProtoPool = ProtoPool::new();
        for class in &self.classes {
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                protos.intern(&pool, &types, &method.method.proto);
                for reloc in &method.relocations {
                    if let Reloc::MethodIndex { method: m, .. } = reloc {
                        protos.intern(&pool, &types, &m.proto);
                    }
                }
            }
        }
        protos.finalize();

        let mut fields: FieldPool = FieldPool::new();
        for class in &self.classes {
            for field in &class.static_fields {
                fields.intern(&types, &pool, &field.field);
            }
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                for reloc in &method.relocations {
                    if let Reloc::FieldIndex { field, .. } = reloc {
                        fields.intern(&types, &pool, field);
                    }
                }
            }
        }
        fields.finalize();

        let mut methods: MethodPool = MethodPool::new();
        for class in &self.classes {
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                methods.intern(&types, &protos, &pool, &method.method);
                for reloc in &method.relocations {
                    if let Reloc::MethodIndex { method: m, .. } = reloc {
                        methods.intern(&types, &protos, &pool, m);
                    }
                }
            }
        }
        methods.finalize();

        self.assemble(&pool, &types, &protos, &fields, &methods)
    }

    fn assemble(
        &self,
        pool: &StringPool,
        types: &TypePool,
        protos: &ProtoPool,
        fields: &FieldPool,
        methods: &MethodPool,
    ) -> Vec<u8> {
        let header_size: usize = 0x70;
        let string_ids_size: u32 = pool.ordered.len() as u32;
        let type_ids_size: u32 = types.ordered.len() as u32;
        let proto_ids_size: u32 = protos.ordered.len() as u32;
        let field_ids_size: u32 = fields.ordered.len() as u32;
        let method_ids_size: u32 = methods.ordered.len() as u32;
        let class_defs_size: u32 = self.classes.len() as u32;

        let string_ids_off: usize = header_size;
        let type_ids_off: usize = string_ids_off + string_ids_size as usize * 4;
        let proto_ids_off: usize = type_ids_off + type_ids_size as usize * 4;
        let field_ids_off: usize = proto_ids_off + proto_ids_size as usize * 12;
        let method_ids_off: usize = field_ids_off + field_ids_size as usize * 8;
        let class_defs_off: usize = method_ids_off + method_ids_size as usize * 8;
        let data_off: usize = class_defs_off + class_defs_size as usize * 32;

        let mut data: Vec<u8> = Vec::new();
        let data_base: usize = data_off;

        let mut string_data_offsets: Vec<u32> = Vec::with_capacity(pool.ordered.len());
        for s in &pool.ordered {
            let off: u32 = (data_base + data.len()) as u32;
            string_data_offsets.push(off);
            write_uleb128(&mut data, mutf8_unit_len(s));
            data.extend_from_slice(&mutf8_encode(s));
            data.push(0);
        }

        let mut type_list_offsets: BTreeMap<Vec<u16>, u32> = BTreeMap::new();
        for proto in &protos.ordered {
            if proto.param_type_ids.is_empty() {
                continue;
            }
            if type_list_offsets.contains_key(&proto.param_type_ids) {
                continue;
            }
            while !(data_base + data.len()).is_multiple_of(4) {
                data.push(0);
            }
            let off: u32 = (data_base + data.len()) as u32;
            data.extend_from_slice(&(proto.param_type_ids.len() as u32).to_le_bytes());
            for tid in &proto.param_type_ids {
                data.extend_from_slice(&tid.to_le_bytes());
            }
            type_list_offsets.insert(proto.param_type_ids.clone(), off);
        }

        let mut code_offsets: BTreeMap<(usize, usize), u32> = BTreeMap::new();
        for (ci, class) in self.classes.iter().enumerate() {
            for (mi, method) in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
                .enumerate()
            {
                if method.insns.is_empty() {
                    continue;
                }
                while !(data_base + data.len()).is_multiple_of(4) {
                    data.push(0);
                }
                let off: u32 = (data_base + data.len()) as u32;
                let mut units: Vec<u16> = method.insns.clone();
                for reloc in &method.relocations {
                    match reloc {
                        Reloc::StringIndex { unit, value } => {
                            units[*unit] = pool.index_of(value) as u16;
                        }
                        Reloc::TypeIndex { unit, descriptor } => {
                            units[*unit] = types.id_of(pool.index_of(descriptor)) as u16;
                        }
                        Reloc::FieldIndex { unit, field } => {
                            units[*unit] = fields.id_of(field) as u16;
                        }
                        Reloc::MethodIndex { unit, method: m } => {
                            units[*unit] = methods.id_of(m) as u16;
                        }
                    }
                }
                data.extend_from_slice(&method.registers_size.to_le_bytes());
                data.extend_from_slice(&method.ins_size.to_le_bytes());
                data.extend_from_slice(&method.outs_size.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                data.extend_from_slice(&0u32.to_le_bytes());
                data.extend_from_slice(&(units.len() as u32).to_le_bytes());
                for unit in &units {
                    data.extend_from_slice(&unit.to_le_bytes());
                }
                code_offsets.insert((ci, mi), off);
            }
        }

        let mut class_data_offsets: Vec<u32> = Vec::with_capacity(self.classes.len());
        let mut static_values_offsets: Vec<u32> = Vec::with_capacity(self.classes.len());
        for (ci, class) in self.classes.iter().enumerate() {
            let sv_off: u32 = if class.static_values.is_empty() {
                0
            } else {
                let off: u32 = (data_base + data.len()) as u32;
                write_encoded_array(&mut data, &class.static_values, pool);
                off
            };
            static_values_offsets.push(sv_off);

            let off: u32 = (data_base + data.len()) as u32;
            write_uleb128(&mut data, class.static_fields.len() as u32);
            write_uleb128(&mut data, 0);
            write_uleb128(&mut data, class.direct_methods.len() as u32);
            write_uleb128(&mut data, class.virtual_methods.len() as u32);

            let mut sorted_fields: Vec<(u32, &EncodedField)> = class
                .static_fields
                .iter()
                .map(|f: &EncodedField| (fields.id_of(&f.field), f))
                .collect();
            sorted_fields.sort_by_key(|(id, _)| *id);
            let mut prev_field: u32 = 0;
            for (j, (field_id, field)) in sorted_fields.iter().enumerate() {
                let diff: u32 = if j == 0 {
                    *field_id
                } else {
                    *field_id - prev_field
                };
                write_uleb128(&mut data, diff);
                write_uleb128(&mut data, field.access_flags);
                prev_field = *field_id;
            }

            let direct_len: usize = class.direct_methods.len();
            emit_encoded_methods(
                &mut data,
                &class.direct_methods,
                methods,
                &code_offsets,
                ci,
                0,
            );
            emit_encoded_methods(
                &mut data,
                &class.virtual_methods,
                methods,
                &code_offsets,
                ci,
                direct_len,
            );

            class_data_offsets.push(off);
        }

        let map_off: u32 = {
            while !(data_off + data.len()).is_multiple_of(4) {
                data.push(0);
            }
            (data_off + data.len()) as u32
        };
        let map_entries: Vec<(u16, u32, u32)> = build_map(
            string_ids_size,
            type_ids_size,
            proto_ids_size,
            field_ids_size,
            method_ids_size,
            class_defs_size,
            string_ids_off as u32,
            type_ids_off as u32,
            proto_ids_off as u32,
            field_ids_off as u32,
            method_ids_off as u32,
            class_defs_off as u32,
            data_off as u32,
            map_off,
        );
        data.extend_from_slice(&(map_entries.len() as u32).to_le_bytes());
        for (ty, size, off) in &map_entries {
            data.extend_from_slice(&ty.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(&size.to_le_bytes());
            data.extend_from_slice(&off.to_le_bytes());
        }

        let data_size: usize = data.len();
        let file_size: usize = data_off + data_size;

        let mut out: Vec<u8> = vec![0u8; data_off];
        out[0..8].copy_from_slice(b"dex\n035\0");
        let mut w = |off: usize, v: u32| {
            out[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        w(32, file_size as u32);
        w(36, header_size as u32);
        w(40, 0x1234_5678);
        w(44, 0);
        w(48, 0);
        w(52, map_off);
        w(56, string_ids_size);
        w(60, string_ids_off as u32);
        w(64, type_ids_size);
        w(68, type_ids_off as u32);
        w(72, proto_ids_size);
        w(76, proto_ids_off as u32);
        w(80, field_ids_size);
        w(84, field_ids_off as u32);
        w(88, method_ids_size);
        w(92, method_ids_off as u32);
        w(96, class_defs_size);
        w(100, class_defs_off as u32);
        w(104, data_size as u32);
        w(108, data_off as u32);

        for (i, off) in string_data_offsets.iter().enumerate() {
            let pos: usize = string_ids_off + i * 4;
            out[pos..pos + 4].copy_from_slice(&off.to_le_bytes());
        }

        for (i, type_descriptor_idx) in types.ordered.iter().enumerate() {
            let pos: usize = type_ids_off + i * 4;
            out[pos..pos + 4].copy_from_slice(&type_descriptor_idx.to_le_bytes());
        }

        for (i, proto) in protos.ordered.iter().enumerate() {
            let pos: usize = proto_ids_off + i * 12;
            out[pos..pos + 4].copy_from_slice(&proto.shorty_idx.to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&proto.return_type_idx.to_le_bytes());
            let params_off: u32 = if proto.param_type_ids.is_empty() {
                0
            } else {
                *type_list_offsets.get(&proto.param_type_ids).unwrap_or(&0)
            };
            out[pos + 8..pos + 12].copy_from_slice(&params_off.to_le_bytes());
        }

        for (i, field) in fields.ordered.iter().enumerate() {
            let pos: usize = field_ids_off + i * 8;
            out[pos..pos + 2].copy_from_slice(&(field.class_type_id as u16).to_le_bytes());
            out[pos + 2..pos + 4].copy_from_slice(&(field.type_id as u16).to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&field.name_idx.to_le_bytes());
        }

        for (i, method) in methods.ordered.iter().enumerate() {
            let pos: usize = method_ids_off + i * 8;
            out[pos..pos + 2].copy_from_slice(&(method.class_type_id as u16).to_le_bytes());
            out[pos + 2..pos + 4].copy_from_slice(&(method.proto_id as u16).to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&method.name_idx.to_le_bytes());
        }

        for (ci, class) in self.classes.iter().enumerate() {
            let pos: usize = class_defs_off + ci * 32;
            let class_type_id: u32 = types.id_of(pool.index_of(&class.class));
            let super_type_id: u32 = types.id_of(pool.index_of(&class.super_class));
            out[pos..pos + 4].copy_from_slice(&class_type_id.to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&class.access_flags.to_le_bytes());
            out[pos + 8..pos + 12].copy_from_slice(&super_type_id.to_le_bytes());
            out[pos + 12..pos + 16].copy_from_slice(&0u32.to_le_bytes());
            out[pos + 16..pos + 20].copy_from_slice(&0u32.to_le_bytes());
            out[pos + 20..pos + 24].copy_from_slice(&0u32.to_le_bytes());
            out[pos + 24..pos + 28].copy_from_slice(&class_data_offsets[ci].to_le_bytes());
            out[pos + 28..pos + 32].copy_from_slice(&static_values_offsets[ci].to_le_bytes());
        }

        out.extend_from_slice(&data);

        let signature: [u8; 20] = sha1(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum: u32 = adler32(&out[12..]);
        out[8..12].copy_from_slice(&checksum.to_le_bytes());

        out
    }
}

fn emit_encoded_methods(
    data: &mut Vec<u8>,
    list: &[EncodedMethod],
    methods: &MethodPool,
    code_offsets: &BTreeMap<(usize, usize), u32>,
    class_index: usize,
    base_method_slot: usize,
) {
    let mut entries: Vec<(u32, u32, u32)> = list
        .iter()
        .enumerate()
        .map(|(j, m): (usize, &EncodedMethod)| {
            let method_id: u32 = methods.id_of(&m.method);
            let code_off: u32 = *code_offsets
                .get(&(class_index, base_method_slot + j))
                .unwrap_or(&0);
            (method_id, m.access_flags, code_off)
        })
        .collect();
    entries.sort_by_key(|(id, _, _)| *id);
    let mut prev: u32 = 0;
    for (k, (method_id, access, code_off)) in entries.iter().enumerate() {
        let diff: u32 = if k == 0 {
            *method_id
        } else {
            *method_id - prev
        };
        write_uleb128(data, diff);
        write_uleb128(data, *access);
        write_uleb128(data, *code_off);
        prev = *method_id;
    }
}

fn write_encoded_array(data: &mut Vec<u8>, values: &[EncodedValue], pool: &StringPool) {
    write_uleb128(data, values.len() as u32);
    for value in values {
        match value {
            EncodedValue::String(content) => {
                let idx: u32 = pool.index_of(content);
                let bytes: [u8; 4] = idx.to_le_bytes();
                let size: usize = value_byte_size(idx);
                let header: u8 = (((size - 1) as u8) << 5) | 0x17;
                data.push(header);
                data.extend_from_slice(&bytes[..size]);
            }
            EncodedValue::Int(v) => {
                let bytes: [u8; 4] = v.to_le_bytes();
                let size: usize = signed_value_byte_size(*v);
                let header: u8 = (((size - 1) as u8) << 5) | 0x04;
                data.push(header);
                data.extend_from_slice(&bytes[..size]);
            }
        }
    }
}

const fn value_byte_size(v: u32) -> usize {
    if v <= 0xFF {
        1
    } else if v <= 0xFFFF {
        2
    } else if v <= 0x00FF_FFFF {
        3
    } else {
        4
    }
}

fn signed_value_byte_size(v: i32) -> usize {
    if (-0x80..=0x7F).contains(&v) {
        1
    } else if (-0x8000..=0x7FFF).contains(&v) {
        2
    } else if (-0x0080_0000..=0x007F_FFFF).contains(&v) {
        3
    } else {
        4
    }
}

#[allow(clippy::too_many_arguments)]
fn build_map(
    string_ids_size: u32,
    type_ids_size: u32,
    proto_ids_size: u32,
    field_ids_size: u32,
    method_ids_size: u32,
    class_defs_size: u32,
    string_ids_off: u32,
    type_ids_off: u32,
    proto_ids_off: u32,
    field_ids_off: u32,
    method_ids_off: u32,
    class_defs_off: u32,
    data_off: u32,
    map_off: u32,
) -> Vec<(u16, u32, u32)> {
    let mut entries: Vec<(u16, u32, u32)> = Vec::new();
    entries.push((0x0000, 1, 0));
    if string_ids_size > 0 {
        entries.push((0x0001, string_ids_size, string_ids_off));
    }
    if type_ids_size > 0 {
        entries.push((0x0002, type_ids_size, type_ids_off));
    }
    if proto_ids_size > 0 {
        entries.push((0x0003, proto_ids_size, proto_ids_off));
    }
    if field_ids_size > 0 {
        entries.push((0x0004, field_ids_size, field_ids_off));
    }
    if method_ids_size > 0 {
        entries.push((0x0005, method_ids_size, method_ids_off));
    }
    if class_defs_size > 0 {
        entries.push((0x0006, class_defs_size, class_defs_off));
    }
    entries.push((0x1000, 1, data_off));
    entries.push((0x1001, 1, map_off));
    entries
}

#[derive(Debug, Clone, Default)]
struct StringPool {
    ordered: Vec<String>,
    seen: std::collections::BTreeSet<String>,
}

impl StringPool {
    fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, value: &str) {
        if self.seen.contains(value) {
            return;
        }
        self.seen.insert(value.to_owned());
        self.ordered.push(value.to_owned());
    }

    fn finalize_order(&mut self) {
        self.ordered.sort();
        self.ordered.dedup();
    }

    fn index_of(&self, value: &str) -> u32 {
        self.ordered
            .binary_search_by(|probe: &String| probe.as_str().cmp(value))
            .map(|i: usize| i as u32)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default)]
struct TypePool {
    descriptor_string_indices: Vec<u32>,
    seen: std::collections::BTreeSet<u32>,
    ordered: Vec<u32>,
    id_by_string_idx: BTreeMap<u32, u32>,
}

impl TypePool {
    fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, pool: &StringPool, descriptor: &str) {
        let sid: u32 = pool.index_of(descriptor);
        if self.seen.contains(&sid) {
            return;
        }
        self.seen.insert(sid);
        self.descriptor_string_indices.push(sid);
    }

    fn finalize(&mut self) {
        self.descriptor_string_indices.sort_unstable();
        self.descriptor_string_indices.dedup();
        self.ordered = self.descriptor_string_indices.clone();
        for (i, sid) in self.ordered.iter().enumerate() {
            self.id_by_string_idx.insert(*sid, i as u32);
        }
    }

    fn id_of(&self, string_idx: u32) -> u32 {
        *self.id_by_string_idx.get(&string_idx).unwrap_or(&0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtoEntry {
    shorty_idx: u32,
    return_type_idx: u32,
    param_type_ids: Vec<u16>,
    sort_key: (u32, Vec<u16>),
}

#[derive(Debug, Clone, Default)]
struct ProtoPool {
    entries: Vec<ProtoEntry>,
    ordered: Vec<ProtoEntry>,
}

impl ProtoPool {
    fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, pool: &StringPool, types: &TypePool, proto: &ProtoRef) {
        let shorty: String = shorty_of(proto);
        let shorty_idx: u32 = pool.index_of(&shorty);
        let return_type_idx: u32 = types.id_of(pool.index_of(&proto.return_type));
        let param_type_ids: Vec<u16> = proto
            .params
            .iter()
            .map(|p: &String| types.id_of(pool.index_of(p)) as u16)
            .collect();
        let entry: ProtoEntry = ProtoEntry {
            shorty_idx,
            return_type_idx,
            param_type_ids: param_type_ids.clone(),
            sort_key: (return_type_idx, param_type_ids),
        };
        if !self
            .entries
            .iter()
            .any(|e: &ProtoEntry| e.sort_key == entry.sort_key)
        {
            self.entries.push(entry);
        }
    }

    fn finalize(&mut self) {
        self.entries
            .sort_by(|a: &ProtoEntry, b: &ProtoEntry| a.sort_key.cmp(&b.sort_key));
        self.ordered = self.entries.clone();
    }

    fn id_of(&self, return_type_idx: u32, param_type_ids: &[u16]) -> u32 {
        self.ordered
            .iter()
            .position(|e: &ProtoEntry| {
                e.return_type_idx == return_type_idx && e.param_type_ids == param_type_ids
            })
            .map(|i: usize| i as u32)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldEntry {
    class_type_id: u32,
    type_id: u32,
    name_idx: u32,
}

#[derive(Debug, Clone, Default)]
struct FieldPool {
    entries: Vec<(FieldEntry, FieldRef)>,
    ordered: Vec<FieldEntry>,
}

impl FieldPool {
    fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, types: &TypePool, pool: &StringPool, field: &FieldRef) {
        let entry: FieldEntry = FieldEntry {
            class_type_id: types.id_of(pool.index_of(&field.class)),
            type_id: types.id_of(pool.index_of(&field.type_desc)),
            name_idx: pool.index_of(&field.name),
        };
        if !self
            .entries
            .iter()
            .any(|(e, _): &(FieldEntry, FieldRef)| *e == entry)
        {
            self.entries.push((entry, field.clone()));
        }
    }

    fn finalize(&mut self) {
        self.entries
            .sort_by(|a: &(FieldEntry, FieldRef), b: &(FieldEntry, FieldRef)| {
                (a.0.class_type_id, a.0.name_idx, a.0.type_id).cmp(&(
                    b.0.class_type_id,
                    b.0.name_idx,
                    b.0.type_id,
                ))
            });
        self.ordered = self.entries.iter().map(|(e, _)| e.clone()).collect();
    }

    fn id_of(&self, field: &FieldRef) -> u32 {
        self.entries
            .iter()
            .position(|(_, f): &(FieldEntry, FieldRef)| f == field)
            .map(|i: usize| i as u32)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MethodEntry {
    class_type_id: u32,
    proto_id: u32,
    name_idx: u32,
}

#[derive(Debug, Clone, Default)]
struct MethodPool {
    entries: Vec<(MethodEntry, MethodRef)>,
    ordered: Vec<MethodEntry>,
}

impl MethodPool {
    fn new() -> Self {
        Self::default()
    }

    fn intern(
        &mut self,
        types: &TypePool,
        protos: &ProtoPool,
        pool: &StringPool,
        method: &MethodRef,
    ) {
        let return_type_idx: u32 = types.id_of(pool.index_of(&method.proto.return_type));
        let param_type_ids: Vec<u16> = method
            .proto
            .params
            .iter()
            .map(|p: &String| types.id_of(pool.index_of(p)) as u16)
            .collect();
        let entry: MethodEntry = MethodEntry {
            class_type_id: types.id_of(pool.index_of(&method.class)),
            proto_id: protos.id_of(return_type_idx, &param_type_ids),
            name_idx: pool.index_of(&method.name),
        };
        if !self
            .entries
            .iter()
            .any(|(e, _): &(MethodEntry, MethodRef)| *e == entry)
        {
            self.entries.push((entry, method.clone()));
        }
    }

    fn finalize(&mut self) {
        self.entries.sort_by(
            |a: &(MethodEntry, MethodRef), b: &(MethodEntry, MethodRef)| {
                (a.0.class_type_id, a.0.name_idx, a.0.proto_id).cmp(&(
                    b.0.class_type_id,
                    b.0.name_idx,
                    b.0.proto_id,
                ))
            },
        );
        self.ordered = self.entries.iter().map(|(e, _)| e.clone()).collect();
    }

    fn id_of(&self, method: &MethodRef) -> u32 {
        self.entries
            .iter()
            .position(|(_, m): &(MethodEntry, MethodRef)| m == method)
            .map(|i: usize| i as u32)
            .unwrap_or(0)
    }
}

fn shorty_of(proto: &ProtoRef) -> String {
    let mut s: String = String::new();
    s.push(shorty_char(&proto.return_type));
    for p in &proto.params {
        s.push(shorty_char(p));
    }
    s
}

fn shorty_char(descriptor: &str) -> char {
    match descriptor.chars().next() {
        Some('[' | 'L') => 'L',
        Some(c) => c,
        None => 'V',
    }
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn mutf8_encode(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() + 1);
    for ch in s.chars() {
        let cp: u32 = ch as u32;
        if cp == 0 {
            out.push(0xC0);
            out.push(0x80);
        } else if cp < 0x80 {
            out.push(cp as u8);
        } else if cp < 0x800 {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else if cp < 0x1_0000 {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else {
            let v: u32 = cp - 0x1_0000;
            let hi: u32 = 0xD800 + (v >> 10);
            let lo: u32 = 0xDC00 + (v & 0x3FF);
            for surrogate in [hi, lo] {
                out.push(0xE0 | (surrogate >> 12) as u8);
                out.push(0x80 | ((surrogate >> 6) & 0x3F) as u8);
                out.push(0x80 | (surrogate & 0x3F) as u8);
            }
        }
    }
    out
}

fn mutf8_unit_len(s: &str) -> u32 {
    s.chars()
        .map(|c: char| if (c as u32) >= 0x1_0000 { 2 } else { 1 })
        .sum()
}

fn base64_encode_standard(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out: String = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0: u8 = chunk[0];
        let b1: u8 = chunk.get(1).copied().unwrap_or(0);
        let b2: u8 = chunk.get(2).copied().unwrap_or(0);
        let n: u32 = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

#[allow(clippy::many_single_char_names)]
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let ml: u64 = (data.len() as u64) * 8;
    let mut msg: Vec<u8> = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w: [u32; 80] = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let base: usize = i * 4;
            *word = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a: u32 = h0;
        let mut b: u32 = h1;
        let mut c: u32 = h2;
        let mut d: u32 = h3;
        let mut e: u32 = h4;

        for (i, word) in w.iter().enumerate() {
            let (f, k): (u32, u32) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp: u32 = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out: [u8; 20] = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[derive(Debug, Clone, Default)]
struct MethodBuilder {
    units: Vec<u16>,
    relocations: Vec<Reloc>,
}

impl MethodBuilder {
    fn op10x(&mut self, op: u8) {
        self.units.extend(insn::fmt10x(op));
    }

    fn op11x(&mut self, op: u8, a: u8) {
        self.units.extend(insn::fmt11x(op, a));
    }

    fn op11n(&mut self, op: u8, a: u8, lit: i8) {
        self.units.extend(insn::fmt11n(op, a, lit));
    }

    fn op12x(&mut self, op: u8, a: u8, b: u8) {
        self.units.extend(insn::fmt12x(op, a, b));
    }

    fn op21s(&mut self, op: u8, a: u8, lit: i16) {
        self.units.extend(insn::fmt21s(op, a, lit));
    }

    fn op23x(&mut self, op: u8, a: u8, b: u8, c: u8) {
        self.units.extend(insn::fmt23x(op, a, b, c));
    }

    fn op22b(&mut self, op: u8, a: u8, b: u8, lit: i8) {
        self.units.extend(insn::fmt22b(op, a, b, lit));
    }

    fn const_string(&mut self, reg: u8, value: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x1A, reg, 0));
        self.relocations.push(Reloc::StringIndex {
            unit,
            value: value.to_owned(),
        });
    }

    fn const_class(&mut self, reg: u8, descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x1C, reg, 0));
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }

    fn check_cast(&mut self, reg: u8, descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x1F, reg, 0));
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }

    fn new_instance(&mut self, reg: u8, descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x22, reg, 0));
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }

    fn new_array(&mut self, dest: u8, size_reg: u8, descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt22c(0x23, dest, size_reg, 0));
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }

    fn sget(&mut self, reg: u8, field: &FieldRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x60, reg, 0));
        self.relocations.push(Reloc::FieldIndex {
            unit,
            field: field.clone(),
        });
    }

    fn sput(&mut self, reg: u8, field: &FieldRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x67, reg, 0));
        self.relocations.push(Reloc::FieldIndex {
            unit,
            field: field.clone(),
        });
    }

    fn sget_object(&mut self, reg: u8, field: &FieldRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x62, reg, 0));
        self.relocations.push(Reloc::FieldIndex {
            unit,
            field: field.clone(),
        });
    }

    fn sput_object(&mut self, reg: u8, field: &FieldRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt21c(0x69, reg, 0));
        self.relocations.push(Reloc::FieldIndex {
            unit,
            field: field.clone(),
        });
    }

    fn invoke_one(&mut self, op: u8, reg: u8, method: &MethodRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt35c_one(op, reg, 0));
        self.relocations.push(Reloc::MethodIndex {
            unit,
            method: method.clone(),
        });
    }

    fn invoke_zero(&mut self, op: u8, method: &MethodRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt35c_zero(op, 0));
        self.relocations.push(Reloc::MethodIndex {
            unit,
            method: method.clone(),
        });
    }

    fn invoke_two(&mut self, op: u8, c: u8, d: u8, method: &MethodRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt35c_two(op, c, d, 0));
        self.relocations.push(Reloc::MethodIndex {
            unit,
            method: method.clone(),
        });
    }

    fn invoke_three(&mut self, op: u8, c: u8, d: u8, e: u8, method: &MethodRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(insn::fmt35c_three(op, c, d, e, 0));
        self.relocations.push(Reloc::MethodIndex {
            unit,
            method: method.clone(),
        });
    }

    const fn mark(&self) -> usize {
        self.units.len()
    }

    fn if_ge(&mut self, a: u8, b: u8) -> usize {
        let pos: usize = self.units.len();
        self.units.extend(insn::fmt22t(0x35, a, b, 0));
        pos
    }

    fn goto_back(&mut self, target: usize) {
        let pos: usize = self.units.len();
        let rel: i8 = (target as i32 - pos as i32) as i8;
        self.units
            .push(u16::from(0x28u8) | (u16::from(rel as u8) << 8));
    }

    fn patch_branch(&mut self, branch_unit_pos: usize, target: usize) {
        let rel: i16 = (target as i32 - branch_unit_pos as i32) as i16;
        self.units[branch_unit_pos + 1] = rel as u16;
    }

    fn fill_array_data_ref(&mut self, array_reg: u8) -> usize {
        let pos: usize = self.units.len();
        self.units.extend(insn::fmt31t(0x26, array_reg, 0));
        pos
    }

    fn emit_byte_array_payload(&mut self, data: &[u8]) -> usize {
        if !self.units.len().is_multiple_of(2) {
            self.units.push(0x0000);
        }
        let pos: usize = self.units.len();
        self.units.push(0x0300);
        self.units.push(1);
        let size: u32 = data.len() as u32;
        self.units.push((size & 0xFFFF) as u16);
        self.units.push((size >> 16) as u16);
        for chunk in data.chunks(2) {
            let lo: u8 = chunk[0];
            let hi: u8 = chunk.get(1).copied().unwrap_or(0);
            self.units.push(u16::from(lo) | (u16::from(hi) << 8));
        }
        pos
    }

    fn patch_payload_ref(&mut self, branch_unit_pos: usize, payload_unit_pos: usize) {
        let rel: i32 = payload_unit_pos as i32 - branch_unit_pos as i32;
        self.units[branch_unit_pos + 1] = (rel as u32 & 0xFFFF) as u16;
        self.units[branch_unit_pos + 2] = ((rel as u32) >> 16) as u16;
    }

    fn filled_new_array(&mut self, regs: &[u8], descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        let capped: &[u8] = &regs[..regs.len().min(3)];
        match capped {
            [] => self.units.extend(insn::fmt35c_zero(0x24, 0)),
            [a] => self.units.extend(insn::fmt35c_one(0x24, *a, 0)),
            [a, b] => self.units.extend(insn::fmt35c_two(0x24, *a, *b, 0)),
            [a, b, c] => self.units.extend(insn::fmt35c_three(0x24, *a, *b, *c, 0)),
            _ => {}
        }
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }
}

#[cfg(test)]
pub(crate) const DEXGUARD_REFLECT_TOOLCHAIN_DEX: &[u8] =
    include_bytes!("../../../corpus/jvm/dexguard/DexGuardReflectStrings.dex");

#[cfg(test)]
pub(crate) const DEXGUARD_REFLECT_TOOLCHAIN_PLAINTEXT: [&str; 6] = [
    "https://api.example.com/v1/auth",
    "X-Api-Key",
    "decryptToken",
    "SELECT * FROM secrets WHERE id = ?",
    "AES/CBC/PKCS5Padding",
    "com.disrobe.sample.Secret",
];

#[must_use]
pub fn dexguard_reflect_sample(plaintexts: &[&str], key: u8) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/DexGuardReflectStrings;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let string_arr: String = "[Ljava/lang/String;".to_owned();
    let char_arr: String = "[C".to_owned();
    let class_t: String = "Ljava/lang/Class;".to_owned();
    let class_arr: String = "[Ljava/lang/Class;".to_owned();
    let method_t: String = "Ljava/lang/reflect/Method;".to_owned();
    let object_arr: String = "[Ljava/lang/Object;".to_owned();
    let integer_t: String = "Ljava/lang/Integer;".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();

    let ciphertexts: Vec<String> = plaintexts
        .iter()
        .map(|p: &&str| {
            p.chars()
                .map(|c: char| char::from_u32((c as u32) ^ u32::from(key)).unwrap_or('\u{FFFD}'))
                .collect::<String>()
        })
        .collect();

    let mut builder: DexBuilder = DexBuilder::new();

    let enc_field: FieldRef = FieldRef {
        class: class.clone(),
        type_desc: string_arr.clone(),
        name: "ENC".to_owned(),
    };

    let mut clinit: MethodBuilder = MethodBuilder::default();
    clinit.op21s(0x13, 0, plaintexts.len() as i16);
    clinit.new_array(0, 0, &string_arr);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        clinit.const_string(1, cipher);
        clinit.op11n(0x12, 2, i as i8);
        clinit.op23x(0x4D, 1, 0, 2);
    }
    clinit.sput_object(0, &enc_field);
    clinit.op10x(0x0E);

    let to_char_array: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: char_arr.clone(),
            params: Vec::new(),
        },
        name: "toCharArray".to_owned(),
    };
    let string_value_of: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![char_arr.clone()],
        },
        name: "valueOf".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.sget_object(0, &enc_field);
    decrypt.op23x(0x46, 0, 0, 5);
    decrypt.invoke_one(0x6E, 0, &to_char_array);
    decrypt.op11x(0x0C, 0);
    decrypt.op12x(0x21, 1, 0);
    decrypt.new_array(2, 1, &char_arr);
    decrypt.op11n(0x12, 3, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(3, 1);
    decrypt.op23x(0x49, 4, 0, 3);
    decrypt.op22b(0xDF, 4, 4, key as i8);
    decrypt.op23x(0x50, 4, 2, 3);
    decrypt.op22b(0xD8, 3, 3, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.invoke_one(0x71, 2, &string_value_of);
    decrypt.op11x(0x0C, 0);
    decrypt.op11x(0x11, 0);

    let get_declared_method: MethodRef = MethodRef {
        class: class_t.clone(),
        proto: ProtoRef {
            return_type: method_t.clone(),
            params: vec![string_t.clone(), class_arr.clone()],
        },
        name: "getDeclaredMethod".to_owned(),
    };
    let integer_value_of: MethodRef = MethodRef {
        class: integer_t.clone(),
        proto: ProtoRef {
            return_type: integer_t.clone(),
            params: vec![int_t.clone()],
        },
        name: "valueOf".to_owned(),
    };
    let method_invoke: MethodRef = MethodRef {
        class: method_t,
        proto: ProtoRef {
            return_type: object.clone(),
            params: vec![object.clone(), object_arr.clone()],
        },
        name: "invoke".to_owned(),
    };
    let integer_type_field: FieldRef = FieldRef {
        class: integer_t,
        type_desc: class_t,
        name: "TYPE".to_owned(),
    };

    let mut fetch: MethodBuilder = MethodBuilder::default();
    fetch.const_class(0, &class);
    fetch.const_string(1, "decrypt");
    fetch.op11n(0x12, 2, 1);
    fetch.new_array(2, 2, &class_arr);
    fetch.op11n(0x12, 3, 0);
    fetch.sget_object(4, &integer_type_field);
    fetch.op23x(0x4D, 4, 2, 3);
    fetch.invoke_three(0x6E, 0, 1, 2, &get_declared_method);
    fetch.op11x(0x0C, 0);
    fetch.op11n(0x12, 1, 1);
    fetch.new_array(1, 1, &object_arr);
    fetch.op11n(0x12, 2, 0);
    fetch.invoke_one(0x71, 6, &integer_value_of);
    fetch.op11x(0x0C, 3);
    fetch.op23x(0x4D, 3, 1, 2);
    fetch.op11n(0x12, 2, 0);
    fetch.invoke_three(0x6E, 0, 2, 1, &method_invoke);
    fetch.op11x(0x0C, 0);
    fetch.check_cast(0, &string_t);
    fetch.op11x(0x11, 0);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t.clone(),
                params: vec![int_t.clone()],
            },
            name: "decrypt".to_owned(),
        },
        access_flags: 0x0009,
        is_direct: false,
        registers_size: 6,
        ins_size: 1,
        outs_size: 1,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let fetch_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t.clone(),
                params: vec![int_t],
            },
            name: "fetch".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 1,
        outs_size: 3,
        insns: fetch.units,
        relocations: fetch.relocations,
    };
    let clinit_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "<clinit>".to_owned(),
        },
        access_flags: 0x10008,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 0,
        insns: clinit.units,
        relocations: clinit.relocations,
    };

    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: vec![EncodedField {
            field: enc_field,
            access_flags: 0x1A,
        }],
        static_values: Vec::new(),
        direct_methods: vec![clinit_method, fetch_method],
        virtual_methods: vec![decrypt_method],
    });

    builder.build()
}

#[must_use]
pub fn dexguard_seeded_random_sample(plaintexts: &[&str]) -> Vec<u8> {
    const RANDOM_SEED: i16 = 1337;
    const RANDOM_KEY: u8 = 120;

    let class: String = "Lcom/disrobe/sample/DexGuardSeededRandom;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let string_arr: String = "[Ljava/lang/String;".to_owned();
    let char_arr: String = "[C".to_owned();
    let random_t: String = "Ljava/util/Random;".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();
    let long_t: String = "J".to_owned();

    let ciphertexts: Vec<String> = plaintexts
        .iter()
        .map(|p: &&str| {
            p.chars()
                .map(|c: char| {
                    char::from_u32((c as u32) ^ u32::from(RANDOM_KEY)).unwrap_or('\u{FFFD}')
                })
                .collect::<String>()
        })
        .collect();

    let mut builder: DexBuilder = DexBuilder::new();
    let enc_field: FieldRef = FieldRef {
        class: class.clone(),
        type_desc: string_arr.clone(),
        name: "ENC".to_owned(),
    };

    let mut clinit: MethodBuilder = MethodBuilder::default();
    clinit.op21s(0x13, 0, plaintexts.len() as i16);
    clinit.new_array(0, 0, &string_arr);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        clinit.const_string(1, cipher);
        clinit.op11n(0x12, 2, i as i8);
        clinit.op23x(0x4D, 1, 0, 2);
    }
    clinit.sput_object(0, &enc_field);
    clinit.op10x(0x0E);

    let to_char_array: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: char_arr.clone(),
            params: Vec::new(),
        },
        name: "toCharArray".to_owned(),
    };
    let string_value_of: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![char_arr.clone()],
        },
        name: "valueOf".to_owned(),
    };
    let random_init: MethodRef = MethodRef {
        class: random_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: vec![long_t],
        },
        name: "<init>".to_owned(),
    };
    let random_next_int: MethodRef = MethodRef {
        class: random_t.clone(),
        proto: ProtoRef {
            return_type: int_t.clone(),
            params: vec![int_t.clone()],
        },
        name: "nextInt".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.new_instance(6, &random_t);
    decrypt.op21s(0x13, 7, RANDOM_SEED);
    decrypt.op11n(0x12, 8, 0);
    decrypt.invoke_three(0x70, 6, 7, 8, &random_init);
    decrypt.op21s(0x13, 7, 127);
    decrypt.invoke_two(0x6E, 6, 7, &random_next_int);
    decrypt.op11x(0x0A, 3);
    decrypt.sget_object(0, &enc_field);
    decrypt.op23x(0x46, 0, 0, 9);
    decrypt.invoke_one(0x6E, 0, &to_char_array);
    decrypt.op11x(0x0C, 0);
    decrypt.op12x(0x21, 1, 0);
    decrypt.new_array(2, 1, &char_arr);
    decrypt.op11n(0x12, 4, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(4, 1);
    decrypt.op23x(0x49, 5, 0, 4);
    decrypt.op23x(0x97, 5, 5, 3);
    decrypt.op23x(0x50, 5, 2, 4);
    decrypt.op22b(0xD8, 4, 4, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.invoke_one(0x71, 2, &string_value_of);
    decrypt.op11x(0x0C, 0);
    decrypt.op11x(0x11, 0);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t,
                params: vec![int_t],
            },
            name: "decrypt".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 10,
        ins_size: 1,
        outs_size: 3,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let clinit_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "<clinit>".to_owned(),
        },
        access_flags: 0x10008,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 0,
        insns: clinit.units,
        relocations: clinit.relocations,
    };

    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: vec![EncodedField {
            field: enc_field,
            access_flags: 0x1A,
        }],
        static_values: Vec::new(),
        direct_methods: vec![clinit_method, decrypt_method],
        virtual_methods: Vec::new(),
    });

    builder.build()
}

#[must_use]
pub fn dexguard_native_key_sample(plaintexts: &[&str], key: u8) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/DexGuardNativeKey;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let string_arr: String = "[Ljava/lang/String;".to_owned();
    let char_arr: String = "[C".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();

    let ciphertexts: Vec<String> = plaintexts
        .iter()
        .map(|p: &&str| {
            p.chars()
                .map(|c: char| char::from_u32((c as u32) ^ u32::from(key)).unwrap_or('\u{FFFD}'))
                .collect::<String>()
        })
        .collect();

    let mut builder: DexBuilder = DexBuilder::new();
    let enc_field: FieldRef = FieldRef {
        class: class.clone(),
        type_desc: string_arr.clone(),
        name: "ENC".to_owned(),
    };

    let mut clinit: MethodBuilder = MethodBuilder::default();
    clinit.op21s(0x13, 0, plaintexts.len() as i16);
    clinit.new_array(0, 0, &string_arr);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        clinit.const_string(1, cipher);
        clinit.op11n(0x12, 2, i as i8);
        clinit.op23x(0x4D, 1, 0, 2);
    }
    clinit.sput_object(0, &enc_field);
    clinit.op10x(0x0E);

    let native_key: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: int_t.clone(),
            params: Vec::new(),
        },
        name: "nativeKey".to_owned(),
    };
    let to_char_array: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: char_arr.clone(),
            params: Vec::new(),
        },
        name: "toCharArray".to_owned(),
    };
    let string_value_of: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![char_arr.clone()],
        },
        name: "valueOf".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.invoke_zero(0x71, &native_key);
    decrypt.op11x(0x0A, 3);
    decrypt.sget_object(0, &enc_field);
    decrypt.op23x(0x46, 0, 0, 7);
    decrypt.invoke_one(0x6E, 0, &to_char_array);
    decrypt.op11x(0x0C, 0);
    decrypt.op12x(0x21, 1, 0);
    decrypt.new_array(2, 1, &char_arr);
    decrypt.op11n(0x12, 4, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(4, 1);
    decrypt.op23x(0x49, 5, 0, 4);
    decrypt.op23x(0x97, 5, 5, 3);
    decrypt.op23x(0x50, 5, 2, 4);
    decrypt.op22b(0xD8, 4, 4, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.invoke_one(0x71, 2, &string_value_of);
    decrypt.op11x(0x0C, 0);
    decrypt.op11x(0x11, 0);

    let native_key_method: EncodedMethod = EncodedMethod {
        method: native_key,
        access_flags: 0x0108,
        is_direct: true,
        registers_size: 0,
        ins_size: 0,
        outs_size: 0,
        insns: Vec::new(),
        relocations: Vec::new(),
    };
    let decrypt_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t,
                params: vec![int_t],
            },
            name: "decrypt".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 8,
        ins_size: 1,
        outs_size: 1,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let clinit_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "<clinit>".to_owned(),
        },
        access_flags: 0x10008,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 0,
        insns: clinit.units,
        relocations: clinit.relocations,
    };

    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: vec![EncodedField {
            field: enc_field,
            access_flags: 0x1A,
        }],
        static_values: Vec::new(),
        direct_methods: vec![clinit_method, native_key_method, decrypt_method],
        virtual_methods: Vec::new(),
    });

    builder.build()
}

#[must_use]
pub fn name_keyed_table_base(class_descriptor: &str) -> i32 {
    let binary: String = class_descriptor
        .strip_prefix('L')
        .and_then(|s: &str| s.strip_suffix(';'))
        .map(|s: &str| s.replace('/', "."))
        .unwrap_or_else(|| class_descriptor.replace('/', "."));
    let mut base: i32 = 0;
    for u in binary.encode_utf16() {
        base = base.wrapping_add(i32::from(u));
    }
    base & 0x7F
}

#[must_use]
pub fn name_keyed_encrypt(plain: &str, class_descriptor: &str) -> String {
    let base: i32 = name_keyed_table_base(class_descriptor);
    let units: Vec<u16> = plain
        .encode_utf16()
        .enumerate()
        .map(|(j, u): (usize, u16)| {
            let k: i32 = (base + i32::try_from(j).unwrap_or(0)) & 0x7F;
            (i32::from(u) ^ k) as u16
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[must_use]
pub fn dexguard_name_keyed_sample(plaintexts: &[&str]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/DexGuardNameKeyed;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let string_arr: String = "[Ljava/lang/String;".to_owned();
    let char_arr: String = "[C".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();

    let ciphertexts: Vec<String> = plaintexts
        .iter()
        .map(|p: &&str| name_keyed_encrypt(p, &class))
        .collect();

    let mut builder: DexBuilder = DexBuilder::new();
    let enc_field: FieldRef = FieldRef {
        class: class.clone(),
        type_desc: string_arr.clone(),
        name: "ENC".to_owned(),
    };

    let mut clinit: MethodBuilder = MethodBuilder::default();
    clinit.op21s(0x13, 0, plaintexts.len() as i16);
    clinit.new_array(0, 0, &string_arr);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        clinit.const_string(1, cipher);
        clinit.op11n(0x12, 2, i as i8);
        clinit.op23x(0x4D, 1, 0, 2);
    }
    clinit.sput_object(0, &enc_field);
    clinit.op10x(0x0E);

    let to_char_array: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: char_arr.clone(),
            params: Vec::new(),
        },
        name: "toCharArray".to_owned(),
    };
    let string_value_of: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![char_arr.clone()],
        },
        name: "valueOf".to_owned(),
    };
    let class_get_name: MethodRef = MethodRef {
        class: "Ljava/lang/Class;".to_owned(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: Vec::new(),
        },
        name: "getName".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.const_class(1, &class);
    decrypt.invoke_one(0x6E, 1, &class_get_name);
    decrypt.op11x(0x0C, 1);
    decrypt.invoke_one(0x6E, 1, &to_char_array);
    decrypt.op11x(0x0C, 1);
    decrypt.op12x(0x21, 2, 1);
    decrypt.op11n(0x12, 3, 0);
    decrypt.op11n(0x12, 4, 0);
    let name_loop: usize = decrypt.mark();
    let name_done: usize = decrypt.if_ge(4, 2);
    decrypt.op23x(0x49, 5, 1, 4);
    decrypt.op23x(0x90, 3, 3, 5);
    decrypt.op22b(0xD8, 4, 4, 1);
    decrypt.goto_back(name_loop);
    let name_done_pos: usize = decrypt.mark();
    decrypt.patch_branch(name_done, name_done_pos);
    decrypt.op22b(0xDD, 3, 3, 0x7F);
    decrypt.sget_object(0, &enc_field);
    decrypt.op23x(0x46, 0, 0, 7);
    decrypt.invoke_one(0x6E, 0, &to_char_array);
    decrypt.op11x(0x0C, 0);
    decrypt.op12x(0x21, 1, 0);
    decrypt.new_array(2, 1, &char_arr);
    decrypt.op11n(0x12, 4, 0);
    let cipher_loop: usize = decrypt.mark();
    let cipher_done: usize = decrypt.if_ge(4, 1);
    decrypt.op23x(0x49, 5, 0, 4);
    decrypt.op23x(0x90, 6, 3, 4);
    decrypt.op22b(0xDD, 6, 6, 0x7F);
    decrypt.op23x(0x97, 5, 5, 6);
    decrypt.op23x(0x50, 5, 2, 4);
    decrypt.op22b(0xD8, 4, 4, 1);
    decrypt.goto_back(cipher_loop);
    let cipher_done_pos: usize = decrypt.mark();
    decrypt.patch_branch(cipher_done, cipher_done_pos);
    decrypt.invoke_one(0x71, 2, &string_value_of);
    decrypt.op11x(0x0C, 0);
    decrypt.op11x(0x11, 0);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t,
                params: vec![int_t],
            },
            name: "decrypt".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 8,
        ins_size: 1,
        outs_size: 1,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let clinit_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "<clinit>".to_owned(),
        },
        access_flags: 0x10008,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 0,
        insns: clinit.units,
        relocations: clinit.relocations,
    };

    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: vec![EncodedField {
            field: enc_field,
            access_flags: 0x1A,
        }],
        static_values: Vec::new(),
        direct_methods: vec![clinit_method, decrypt_method],
        virtual_methods: Vec::new(),
    });

    builder.build()
}

fn xor_bytearray_decrypt_body(descriptor_class: &str) -> (MethodRef, MethodBuilder) {
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let int_t: String = "I".to_owned();
    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };
    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.op12x(0x21, 0, 5);
    decrypt.new_array(1, 0, &byte_arr);
    decrypt.op11n(0x12, 2, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(2, 0);
    decrypt.op23x(0x48, 3, 5, 2);
    decrypt.op12x(0xB7, 3, 6);
    decrypt.op23x(0x4F, 3, 1, 2);
    decrypt.op22b(0xD8, 2, 2, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.new_instance(4, &string_t);
    decrypt.invoke_two(0x70, 4, 1, &string_init);
    decrypt.op11x(0x11, 4);
    let decrypt_ref: MethodRef = MethodRef {
        class: descriptor_class.to_owned(),
        proto: ProtoRef {
            return_type: string_t,
            params: vec![byte_arr, int_t],
        },
        name: "decrypt".to_owned(),
    };
    (decrypt_ref, decrypt)
}

#[must_use]
pub fn xor_bytearray_callsite_sample(pairs: &[(&[u8], u8)]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericXorCallsite;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let void_t: String = "V".to_owned();
    let byte_arr: String = "[B".to_owned();

    let (decrypt_ref, decrypt): (MethodRef, MethodBuilder) = xor_bytearray_decrypt_body(&class);

    let mut caller: MethodBuilder = MethodBuilder::default();
    for (cipher, key) in pairs {
        caller.op21s(0x13, 0, cipher.len() as i16);
        caller.new_array(0, 0, &byte_arr);
        let branch_pos: usize = caller.fill_array_data_ref(0);
        let payload_pos: usize = caller.emit_byte_array_payload(cipher);
        caller.patch_payload_ref(branch_pos, payload_pos);
        caller.op21s(0x13, 1, i16::from(*key));
        caller.invoke_two(0x71, 0, 1, &decrypt_ref);
        caller.op11x(0x0C, 2);
    }
    caller.op10x(0x0E);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: decrypt_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 2,
        outs_size: 2,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 2,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![decrypt_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

pub const CLINIT_KEY_TABLE_DERIVED_KEY: u8 = 0x11;

#[must_use]
pub fn clinit_key_table_sample(ciphers: &[&[u8]]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericClinitKey;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();

    let key_field: FieldRef = FieldRef {
        class: class.clone(),
        type_desc: int_t,
        name: "KEY".to_owned(),
    };

    let mut clinit: MethodBuilder = MethodBuilder::default();
    clinit.op21s(0x13, 0, 0x50);
    clinit.op21s(0x13, 1, 0x41);
    clinit.op12x(0xB7, 0, 1);
    clinit.sput(0, &key_field);
    clinit.op10x(0x0E);

    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };
    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.sget(4, &key_field);
    decrypt.op12x(0x21, 0, 6);
    decrypt.new_array(1, 0, &byte_arr);
    decrypt.op11n(0x12, 2, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(2, 0);
    decrypt.op23x(0x48, 3, 6, 2);
    decrypt.op12x(0xB7, 3, 4);
    decrypt.op23x(0x4F, 3, 1, 2);
    decrypt.op22b(0xD8, 2, 2, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.new_instance(5, &string_t);
    decrypt.invoke_two(0x70, 5, 1, &string_init);
    decrypt.op11x(0x11, 5);

    let decrypt_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t,
            params: vec![byte_arr.clone()],
        },
        name: "decrypt".to_owned(),
    };

    let mut caller: MethodBuilder = MethodBuilder::default();
    for cipher in ciphers {
        caller.op21s(0x13, 0, cipher.len() as i16);
        caller.new_array(0, 0, &byte_arr);
        let branch_pos: usize = caller.fill_array_data_ref(0);
        let payload_pos: usize = caller.emit_byte_array_payload(cipher);
        caller.patch_payload_ref(branch_pos, payload_pos);
        caller.invoke_one(0x71, 0, &decrypt_ref);
        caller.op11x(0x0C, 1);
    }
    caller.op10x(0x0E);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: decrypt_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 1,
        outs_size: 2,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let clinit_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t.clone(),
                params: Vec::new(),
            },
            name: "<clinit>".to_owned(),
        },
        access_flags: 0x10008,
        is_direct: true,
        registers_size: 2,
        ins_size: 0,
        outs_size: 0,
        insns: clinit.units,
        relocations: clinit.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 2,
        ins_size: 0,
        outs_size: 1,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: vec![EncodedField {
            field: key_field,
            access_flags: 0x1A,
        }],
        static_values: Vec::new(),
        direct_methods: vec![clinit_method, decrypt_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn stringbuilder_decrypt_sample(pairs: &[(&[u8], u8)]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericStringBuilder;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let builder_t: String = "Ljava/lang/StringBuilder;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();
    let char_t: String = "C".to_owned();

    let sb_init: MethodRef = MethodRef {
        class: builder_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: Vec::new(),
        },
        name: "<init>".to_owned(),
    };
    let sb_append_char: MethodRef = MethodRef {
        class: builder_t.clone(),
        proto: ProtoRef {
            return_type: builder_t.clone(),
            params: vec![char_t],
        },
        name: "append".to_owned(),
    };
    let sb_to_string: MethodRef = MethodRef {
        class: builder_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: Vec::new(),
        },
        name: "toString".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.op12x(0x21, 0, 5);
    decrypt.new_instance(1, &builder_t);
    decrypt.invoke_one(0x70, 1, &sb_init);
    decrypt.op11n(0x12, 2, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(2, 0);
    decrypt.op23x(0x48, 3, 5, 2);
    decrypt.op12x(0xB7, 3, 6);
    decrypt.op12x(0x8E, 3, 3);
    decrypt.invoke_two(0x6E, 1, 3, &sb_append_char);
    decrypt.op22b(0xD8, 2, 2, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.invoke_one(0x6E, 1, &sb_to_string);
    decrypt.op11x(0x0C, 4);
    decrypt.op11x(0x11, 4);

    let decrypt_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t,
            params: vec![byte_arr.clone(), int_t],
        },
        name: "decrypt".to_owned(),
    };

    let mut caller: MethodBuilder = MethodBuilder::default();
    for (cipher, key) in pairs {
        caller.op21s(0x13, 0, cipher.len() as i16);
        caller.new_array(0, 0, &byte_arr);
        let branch_pos: usize = caller.fill_array_data_ref(0);
        let payload_pos: usize = caller.emit_byte_array_payload(cipher);
        caller.patch_payload_ref(branch_pos, payload_pos);
        caller.op21s(0x13, 1, i16::from(*key));
        caller.invoke_two(0x71, 0, 1, &decrypt_ref);
        caller.op11x(0x0C, 2);
    }
    caller.op10x(0x0E);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: decrypt_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 2,
        outs_size: 2,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 2,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![decrypt_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn base64_xor_chain_sample(pairs: &[(&str, u8)]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericBase64Xor;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();
    let base64_t: String = "Landroid/util/Base64;".to_owned();

    let base64_decode: MethodRef = MethodRef {
        class: base64_t,
        proto: ProtoRef {
            return_type: byte_arr.clone(),
            params: vec![string_t.clone(), int_t.clone()],
        },
        name: "decode".to_owned(),
    };
    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.op11n(0x12, 1, 0);
    decrypt.invoke_two(0x71, 6, 1, &base64_decode);
    decrypt.op11x(0x0C, 0);
    decrypt.op12x(0x21, 1, 0);
    decrypt.new_array(2, 1, &byte_arr);
    decrypt.op11n(0x12, 3, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(3, 1);
    decrypt.op23x(0x48, 4, 0, 3);
    decrypt.op12x(0xB7, 4, 7);
    decrypt.op23x(0x4F, 4, 2, 3);
    decrypt.op22b(0xD8, 3, 3, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.new_instance(5, &string_t);
    decrypt.invoke_two(0x70, 5, 2, &string_init);
    decrypt.op11x(0x11, 5);

    let decrypt_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![string_t.clone(), int_t],
        },
        name: "decrypt".to_owned(),
    };

    let mut caller: MethodBuilder = MethodBuilder::default();
    for (plain, key) in pairs {
        let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
        let b64: String = base64_encode_standard(&cipher);
        caller.const_string(0, &b64);
        caller.op21s(0x13, 1, i16::from(*key));
        caller.invoke_two(0x71, 0, 1, &decrypt_ref);
        caller.op11x(0x0C, 2);
    }
    caller.op10x(0x0E);

    let decrypt_method: EncodedMethod = EncodedMethod {
        method: decrypt_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 8,
        ins_size: 2,
        outs_size: 2,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 2,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![decrypt_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn chained_double_decrypt_sample(cipher: &[u8], k1: u8, k2: u8) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericChainedDecrypt;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let char_arr: String = "[C".to_owned();
    let void_t: String = "V".to_owned();

    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };
    let mut stage1: MethodBuilder = MethodBuilder::default();
    stage1.op12x(0x21, 0, 6);
    stage1.new_array(1, 0, &byte_arr);
    stage1.op11n(0x12, 2, 0);
    let s1_loop: usize = stage1.mark();
    let s1_if_ge: usize = stage1.if_ge(2, 0);
    stage1.op23x(0x48, 3, 6, 2);
    stage1.op22b(0xDF, 3, 3, k1 as i8);
    stage1.op23x(0x4F, 3, 1, 2);
    stage1.op22b(0xD8, 2, 2, 1);
    stage1.goto_back(s1_loop);
    let s1_done: usize = stage1.mark();
    stage1.patch_branch(s1_if_ge, s1_done);
    stage1.new_instance(4, &string_t);
    stage1.invoke_two(0x70, 4, 1, &string_init);
    stage1.op11x(0x11, 4);

    let stage1_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![byte_arr.clone()],
        },
        name: "stage1".to_owned(),
    };

    let to_char_array: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: char_arr.clone(),
            params: Vec::new(),
        },
        name: "toCharArray".to_owned(),
    };
    let string_value_of: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![char_arr.clone()],
        },
        name: "valueOf".to_owned(),
    };
    let mut stage2: MethodBuilder = MethodBuilder::default();
    stage2.invoke_one(0x6E, 6, &to_char_array);
    stage2.op11x(0x0C, 0);
    stage2.op12x(0x21, 1, 0);
    stage2.new_array(2, 1, &char_arr);
    stage2.op11n(0x12, 3, 0);
    let s2_loop: usize = stage2.mark();
    let s2_if_ge: usize = stage2.if_ge(3, 1);
    stage2.op23x(0x49, 4, 0, 3);
    stage2.op22b(0xDF, 4, 4, k2 as i8);
    stage2.op23x(0x50, 4, 2, 3);
    stage2.op22b(0xD8, 3, 3, 1);
    stage2.goto_back(s2_loop);
    let s2_done: usize = stage2.mark();
    stage2.patch_branch(s2_if_ge, s2_done);
    stage2.invoke_one(0x71, 2, &string_value_of);
    stage2.op11x(0x0C, 5);
    stage2.op11x(0x11, 5);

    let stage2_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t.clone(),
            params: vec![string_t.clone()],
        },
        name: "stage2".to_owned(),
    };

    let mut caller: MethodBuilder = MethodBuilder::default();
    caller.op21s(0x13, 0, cipher.len() as i16);
    caller.new_array(0, 0, &byte_arr);
    let branch_pos: usize = caller.fill_array_data_ref(0);
    let payload_pos: usize = caller.emit_byte_array_payload(cipher);
    caller.patch_payload_ref(branch_pos, payload_pos);
    caller.invoke_one(0x71, 0, &stage1_ref);
    caller.op11x(0x0C, 1);
    caller.invoke_one(0x71, 1, &stage2_ref);
    caller.op11x(0x0C, 2);
    caller.op10x(0x0E);

    let stage1_method: EncodedMethod = EncodedMethod {
        method: stage1_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 1,
        outs_size: 2,
        insns: stage1.units,
        relocations: stage1.relocations,
    };
    let stage2_method: EncodedMethod = EncodedMethod {
        method: stage2_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 1,
        outs_size: 1,
        insns: stage2.units,
        relocations: stage2.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 1,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![stage1_method, stage2_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn native_call_wall_sample(cipher: &[u8]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericNativeWall;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let void_t: String = "V".to_owned();
    let int_t: String = "I".to_owned();

    let native_key: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: int_t,
            params: Vec::new(),
        },
        name: "nativeKey".to_owned(),
    };
    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: void_t.clone(),
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };

    let mut decrypt: MethodBuilder = MethodBuilder::default();
    decrypt.invoke_zero(0x71, &native_key);
    decrypt.op11x(0x0A, 4);
    decrypt.op12x(0x21, 0, 6);
    decrypt.new_array(1, 0, &byte_arr);
    decrypt.op11n(0x12, 2, 0);
    let loop_start: usize = decrypt.mark();
    let if_ge_pos: usize = decrypt.if_ge(2, 0);
    decrypt.op23x(0x48, 3, 6, 2);
    decrypt.op12x(0xB7, 3, 4);
    decrypt.op23x(0x4F, 3, 1, 2);
    decrypt.op22b(0xD8, 2, 2, 1);
    decrypt.goto_back(loop_start);
    let done_pos: usize = decrypt.mark();
    decrypt.patch_branch(if_ge_pos, done_pos);
    decrypt.new_instance(6, &string_t);
    decrypt.invoke_two(0x70, 6, 1, &string_init);
    decrypt.op11x(0x11, 6);

    let decrypt_ref: MethodRef = MethodRef {
        class: class.clone(),
        proto: ProtoRef {
            return_type: string_t,
            params: vec![byte_arr.clone()],
        },
        name: "decrypt".to_owned(),
    };

    let mut caller: MethodBuilder = MethodBuilder::default();
    caller.op21s(0x13, 0, cipher.len() as i16);
    caller.new_array(0, 0, &byte_arr);
    let branch_pos: usize = caller.fill_array_data_ref(0);
    let payload_pos: usize = caller.emit_byte_array_payload(cipher);
    caller.patch_payload_ref(branch_pos, payload_pos);
    caller.invoke_one(0x71, 0, &decrypt_ref);
    caller.op11x(0x0C, 1);
    caller.op10x(0x0E);

    let native_key_method: EncodedMethod = EncodedMethod {
        method: native_key,
        access_flags: 0x0108,
        is_direct: true,
        registers_size: 0,
        ins_size: 0,
        outs_size: 0,
        insns: Vec::new(),
        relocations: Vec::new(),
    };
    let decrypt_method: EncodedMethod = EncodedMethod {
        method: decrypt_ref,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 1,
        outs_size: 2,
        insns: decrypt.units,
        relocations: decrypt.relocations,
    };
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 2,
        ins_size: 0,
        outs_size: 1,
        insns: caller.units,
        relocations: caller.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![native_key_method, decrypt_method, caller_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn filled_new_array_string_sample(bytes: [u8; 3]) -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericFilledNewArray;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let string_t: String = "Ljava/lang/String;".to_owned();
    let byte_arr: String = "[B".to_owned();
    let void_t: String = "V".to_owned();

    let string_init: MethodRef = MethodRef {
        class: string_t.clone(),
        proto: ProtoRef {
            return_type: void_t,
            params: vec![byte_arr.clone()],
        },
        name: "<init>".to_owned(),
    };

    let mut demo: MethodBuilder = MethodBuilder::default();
    demo.op21s(0x13, 0, i16::from(bytes[0]));
    demo.op21s(0x13, 1, i16::from(bytes[1]));
    demo.op21s(0x13, 2, i16::from(bytes[2]));
    demo.filled_new_array(&[0, 1, 2], &byte_arr);
    demo.op11x(0x0C, 3);
    demo.new_instance(4, &string_t);
    demo.invoke_two(0x70, 4, 3, &string_init);
    demo.op11x(0x11, 4);

    let demo_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: string_t,
                params: Vec::new(),
            },
            name: "demo".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 5,
        ins_size: 0,
        outs_size: 2,
        insns: demo.units,
        relocations: demo.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![demo_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn infinite_loop_sample() -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericInfiniteLoop;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let int_t: String = "I".to_owned();

    let mut spin: MethodBuilder = MethodBuilder::default();
    spin.op11n(0x12, 0, 0);
    let loop_start: usize = spin.mark();
    spin.op22b(0xD8, 0, 0, 1);
    spin.goto_back(loop_start);

    let spin_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: int_t,
                params: Vec::new(),
            },
            name: "spin".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        insns: spin.units,
        relocations: spin.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![spin_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

#[must_use]
pub fn heap_bomb_sample() -> Vec<u8> {
    let class: String = "Lcom/disrobe/sample/GenericHeapBomb;".to_owned();
    let object: String = "Ljava/lang/Object;".to_owned();
    let void_t: String = "V".to_owned();
    let byte_arr: String = "[B".to_owned();

    let mut bomb: MethodBuilder = MethodBuilder::default();
    bomb.op21s(0x13, 0, 32_767);
    let loop_start: usize = bomb.mark();
    bomb.new_array(1, 0, &byte_arr);
    bomb.goto_back(loop_start);

    let bomb_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: class.clone(),
            proto: ProtoRef {
                return_type: void_t,
                params: Vec::new(),
            },
            name: "bomb".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 2,
        ins_size: 0,
        outs_size: 0,
        insns: bomb.units,
        relocations: bomb.relocations,
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class,
        super_class: object,
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![bomb_method],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

pub mod insn {
    #[must_use]
    pub fn fmt10x(op: u8) -> Vec<u16> {
        vec![u16::from(op)]
    }

    #[must_use]
    pub fn fmt12x(op: u8, a: u8, b: u8) -> Vec<u16> {
        vec![u16::from(op) | (u16::from(a & 0xF) << 8) | (u16::from(b & 0xF) << 12)]
    }

    #[must_use]
    pub fn fmt11n(op: u8, a: u8, lit: i8) -> Vec<u16> {
        let n: u16 = u16::from((lit as u8) & 0xF);
        vec![u16::from(op) | (u16::from(a & 0xF) << 8) | (n << 12)]
    }

    #[must_use]
    pub fn fmt11x(op: u8, a: u8) -> Vec<u16> {
        vec![u16::from(op) | (u16::from(a) << 8)]
    }

    #[must_use]
    pub fn fmt21s(op: u8, a: u8, lit: i16) -> Vec<u16> {
        vec![u16::from(op) | (u16::from(a) << 8), lit as u16]
    }

    #[must_use]
    pub fn fmt21c(op: u8, a: u8, index: u16) -> Vec<u16> {
        vec![u16::from(op) | (u16::from(a) << 8), index]
    }

    #[must_use]
    pub fn fmt22b(op: u8, a: u8, b: u8, lit: i8) -> Vec<u16> {
        vec![
            u16::from(op) | (u16::from(a) << 8),
            u16::from(b) | (u16::from(lit as u8) << 8),
        ]
    }

    #[must_use]
    pub fn fmt22c(op: u8, a: u8, b: u8, index: u16) -> Vec<u16> {
        vec![
            u16::from(op) | (u16::from(a & 0xF) << 8) | (u16::from(b & 0xF) << 12),
            index,
        ]
    }

    #[must_use]
    pub fn fmt22t(op: u8, a: u8, b: u8, branch_units: i16) -> Vec<u16> {
        vec![
            u16::from(op) | (u16::from(a & 0xF) << 8) | (u16::from(b & 0xF) << 12),
            branch_units as u16,
        ]
    }

    #[must_use]
    pub fn fmt23x(op: u8, a: u8, b: u8, c: u8) -> Vec<u16> {
        vec![
            u16::from(op) | (u16::from(a) << 8),
            u16::from(b) | (u16::from(c) << 8),
        ]
    }

    #[must_use]
    pub fn fmt31t(op: u8, a: u8, offset_units: i32) -> Vec<u16> {
        vec![
            u16::from(op) | (u16::from(a) << 8),
            (offset_units as u32 & 0xFFFF) as u16,
            ((offset_units as u32) >> 16) as u16,
        ]
    }

    #[must_use]
    pub fn fmt35c_zero(op: u8, index: u16) -> Vec<u16> {
        vec![u16::from(op), index, 0]
    }

    #[must_use]
    pub fn fmt35c_one(op: u8, reg: u8, index: u16) -> Vec<u16> {
        vec![u16::from(op) | (1u16 << 12), index, u16::from(reg & 0xF)]
    }

    #[must_use]
    pub fn fmt35c_two(op: u8, c: u8, d: u8, index: u16) -> Vec<u16> {
        let packed: u16 = u16::from(c & 0xF) | (u16::from(d & 0xF) << 4);
        vec![u16::from(op) | (2u16 << 12), index, packed]
    }

    #[must_use]
    pub fn fmt35c_three(op: u8, c: u8, d: u8, e: u8, index: u16) -> Vec<u16> {
        let packed: u16 =
            u16::from(c & 0xF) | (u16::from(d & 0xF) << 4) | (u16::from(e & 0xF) << 8);
        vec![u16::from(op) | (3u16 << 12), index, packed]
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        let digest: [u8; 20] = sha1(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn adler32_known_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn uleb128_roundtrip_small() {
        let mut buf: Vec<u8> = Vec::new();
        write_uleb128(&mut buf, 624_485);
        assert_eq!(buf, vec![0xE5, 0x8E, 0x26]);
    }

    #[test]
    fn sample_parses_as_valid_dex() {
        let plaintexts: [&str; 2] = ["hello world", "secret"];
        let dex: Vec<u8> = dexguard_reflect_sample(&plaintexts, 0x66);
        assert_eq!(&dex[..4], b"dex\n");
        let parsed: crate::dex::DexFile = crate::dex::parse(&dex).expect("dex parses");
        assert_eq!(parsed.header.checksum, adler32(&dex[12..]));
        assert!(
            parsed
                .class_descriptors
                .iter()
                .any(|c: &String| c == "Lcom/disrobe/sample/DexGuardReflectStrings;")
        );
        let code_items: Vec<crate::dex::CodeItem> = crate::dex::parse_code_items(&parsed, &dex)
            .into_complete()
            .expect("builder output must decode");
        assert!(
            code_items
                .iter()
                .any(|c: &crate::dex::CodeItem| c.method_name == "decrypt")
        );
        assert!(
            code_items
                .iter()
                .any(|c: &crate::dex::CodeItem| c.method_name == "<clinit>")
        );
    }
}
