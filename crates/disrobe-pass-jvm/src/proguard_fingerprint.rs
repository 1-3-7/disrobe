use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{Operands, disassemble};
use crate::classfile::{ClassFile, ConstantPoolEntry, MethodInfo};

const ACC_STATIC: u16 = 0x0008;
const ACC_FINAL: u16 = 0x0010;
const MIN_METHOD_SCORE: f64 = 0.82;
const MIN_CLASS_SCORE: f64 = 0.60;
const MIN_CLASS_MARGIN: f64 = 0.08;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodSignature {
    pub descriptor: String,
    pub is_static: bool,
    pub opcode_skeleton: Vec<u8>,
    pub string_constants: BTreeSet<String>,
    pub numeric_constants: BTreeSet<i64>,
    pub referenced_descriptors: BTreeSet<String>,
    pub stable_owners: BTreeSet<String>,
    pub stable_member_names: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSignature {
    pub descriptor: String,
    pub is_static: bool,
    pub is_final: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassSignature {
    pub name: String,
    pub stable_super: Option<String>,
    pub stable_interfaces: BTreeSet<String>,
    pub field_shapes: BTreeMap<String, usize>,
    pub class_strings: BTreeSet<String>,
    pub class_numbers: BTreeSet<i64>,
    pub methods: Vec<MethodSignature>,
    pub method_names: Vec<String>,
    pub fields: Vec<FieldSignature>,
    pub field_names: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibrarySignatureSet {
    pub classes: Vec<ClassSignature>,
}

impl LibrarySignatureSet {
    #[must_use]
    pub fn from_classfiles(classes: &[ClassFile]) -> Self {
        let mut out: Vec<ClassSignature> = Vec::with_capacity(classes.len());
        for cf in classes {
            out.push(signature_for_class(cf));
        }
        Self { classes: out }
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReidentifiedMethod {
    pub obfuscated_name: String,
    pub descriptor: String,
    pub original_name: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReidentifiedClass {
    pub obfuscated_name: String,
    pub original_name: String,
    pub score: f64,
    pub methods: Vec<ReidentifiedMethod>,
    pub fields: Vec<ReidentifiedField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReidentifiedField {
    pub obfuscated_name: String,
    pub descriptor: String,
    pub original_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FingerprintReport {
    pub classes: Vec<ReidentifiedClass>,
}

impl FingerprintReport {
    #[inline]
    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }

    #[inline]
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.classes
            .iter()
            .map(|c: &ReidentifiedClass| c.methods.len())
            .sum()
    }

    #[must_use]
    pub fn original_for_obfuscated_class(&self, obfuscated_internal: &str) -> Option<&str> {
        self.classes
            .iter()
            .find(|c: &&ReidentifiedClass| c.obfuscated_name == obfuscated_internal)
            .map(|c: &ReidentifiedClass| c.original_name.as_str())
    }
}

#[must_use]
pub fn is_stable_type(internal_or_descriptor: &str) -> bool {
    let trimmed: &str = internal_or_descriptor.trim_start_matches('[');
    let core: &str = trimmed
        .strip_prefix('L')
        .map_or(trimmed, |rest: &str| rest.strip_suffix(';').unwrap_or(rest));
    core.starts_with("java/")
        || core.starts_with("javax/")
        || core.starts_with("kotlin/")
        || core.starts_with("android/")
        || core.starts_with("androidx/")
        || core.starts_with("sun/")
        || core.starts_with("jdk/")
}

fn stable_descriptor(descriptor: &str) -> String {
    let bytes: &[u8] = descriptor.as_bytes();
    let mut out: String = String::with_capacity(descriptor.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                let Some(rel): Option<usize> = descriptor[i..].find(';') else {
                    out.push('L');
                    i += 1;
                    continue;
                };
                let end: usize = i + rel;
                let internal: &str = &descriptor[i + 1..end];
                if is_stable_type(internal) {
                    out.push('L');
                    out.push_str(internal);
                    out.push(';');
                } else {
                    out.push('#');
                }
                i = end + 1;
            }
            other => {
                out.push(other as char);
                i += 1;
            }
        }
    }
    out
}

fn signature_for_class(cf: &ClassFile) -> ClassSignature {
    let name: String = cf.this_class_name().unwrap_or("").to_owned();
    let stable_super: Option<String> = (cf.super_class != 0)
        .then(|| cf.class_name(cf.super_class).ok())
        .flatten()
        .filter(|s: &&str| is_stable_type(s))
        .map(str::to_owned);
    let mut stable_interfaces: BTreeSet<String> = BTreeSet::new();
    for iface in &cf.interfaces {
        if let Ok(n) = cf.class_name(*iface)
            && is_stable_type(n)
        {
            stable_interfaces.insert(n.to_owned());
        }
    }
    let mut field_shapes: BTreeMap<String, usize> = BTreeMap::new();
    let mut fields: Vec<FieldSignature> = Vec::with_capacity(cf.fields.len());
    let mut field_names: Vec<String> = Vec::with_capacity(cf.fields.len());
    for field in &cf.fields {
        let Ok(desc): Result<&str, _> = cf.utf8_at(field.descriptor_index) else {
            continue;
        };
        let Ok(fname): Result<&str, _> = cf.utf8_at(field.name_index) else {
            continue;
        };
        let shape: String = stable_descriptor(desc);
        *field_shapes.entry(shape).or_insert(0) += 1;
        fields.push(FieldSignature {
            descriptor: desc.to_owned(),
            is_static: field.access_flags & ACC_STATIC != 0,
            is_final: field.access_flags & ACC_FINAL != 0,
        });
        field_names.push(fname.to_owned());
    }
    let mut class_strings: BTreeSet<String> = BTreeSet::new();
    let mut class_numbers: BTreeSet<i64> = BTreeSet::new();
    let mut methods: Vec<MethodSignature> = Vec::with_capacity(cf.methods.len());
    let mut method_names: Vec<String> = Vec::with_capacity(cf.methods.len());
    for method in &cf.methods {
        let Ok(mname): Result<&str, _> = cf.utf8_at(method.name_index) else {
            continue;
        };
        if let Some(sig) = method_signature(cf, method) {
            class_strings.extend(sig.string_constants.iter().cloned());
            class_numbers.extend(sig.numeric_constants.iter().copied());
            methods.push(sig);
            method_names.push(mname.to_owned());
        }
    }
    collect_constant_pool_anchors(cf, &mut class_strings, &mut class_numbers);
    ClassSignature {
        name,
        stable_super,
        stable_interfaces,
        field_shapes,
        class_strings,
        class_numbers,
        methods,
        method_names,
        fields,
        field_names,
    }
}

fn collect_constant_pool_anchors(
    cf: &ClassFile,
    strings: &mut BTreeSet<String>,
    numbers: &mut BTreeSet<i64>,
) {
    for entry in &cf.constant_pool {
        match entry {
            ConstantPoolEntry::String { utf8_index } => {
                if let Ok(s) = cf.utf8_at(*utf8_index) {
                    strings.insert(s.to_owned());
                }
            }
            ConstantPoolEntry::Integer(v) => {
                numbers.insert(i64::from(*v));
            }
            ConstantPoolEntry::Long(v) => {
                numbers.insert(*v);
            }
            _ => {}
        }
    }
}

fn raw_code(cf: &ClassFile, method: &MethodInfo) -> Option<Vec<u8>> {
    for attr in &method.attributes {
        if cf.utf8_at(attr.name_index).ok()? == "Code" {
            let info: &[u8] = &attr.info;
            if info.len() < 8 {
                return None;
            }
            let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
            let start: usize = 8;
            let end: usize = start.checked_add(code_len)?;
            if end > info.len() {
                return None;
            }
            return Some(info[start..end].to_vec());
        }
    }
    None
}

fn method_signature(cf: &ClassFile, method: &MethodInfo) -> Option<MethodSignature> {
    let descriptor: String = cf.utf8_at(method.descriptor_index).ok()?.to_owned();
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let Some(code): Option<Vec<u8>> = raw_code(cf, method) else {
        return Some(MethodSignature {
            descriptor: stable_descriptor(&descriptor),
            is_static,
            opcode_skeleton: Vec::new(),
            string_constants: BTreeSet::new(),
            numeric_constants: BTreeSet::new(),
            referenced_descriptors: BTreeSet::new(),
            stable_owners: BTreeSet::new(),
            stable_member_names: BTreeSet::new(),
        });
    };
    let instrs: Vec<crate::bytecode::Instruction> = disassemble(&code).ok()?;
    let mut opcode_skeleton: Vec<u8> = Vec::with_capacity(instrs.len());
    let mut string_constants: BTreeSet<String> = BTreeSet::new();
    let mut numeric_constants: BTreeSet<i64> = BTreeSet::new();
    let mut referenced_descriptors: BTreeSet<String> = BTreeSet::new();
    let mut stable_owners: BTreeSet<String> = BTreeSet::new();
    let mut stable_member_names: BTreeSet<String> = BTreeSet::new();
    for insn in &instrs {
        opcode_skeleton.push(insn.opcode);
        match &insn.operands {
            Operands::ConstPool(idx) => {
                harvest_const(cf, *idx, &mut string_constants, &mut numeric_constants);
                harvest_ref(
                    cf,
                    *idx,
                    &mut referenced_descriptors,
                    &mut stable_owners,
                    &mut stable_member_names,
                );
            }
            Operands::InvokeInterface { index, .. }
            | Operands::InvokeDynamic(index)
            | Operands::MultiANewArray { index, .. } => {
                harvest_ref(
                    cf,
                    *index,
                    &mut referenced_descriptors,
                    &mut stable_owners,
                    &mut stable_member_names,
                );
            }
            Operands::Byte(v) | Operands::Short(v) => {
                numeric_constants.insert(i64::from(*v));
            }
            _ => {}
        }
    }
    Some(MethodSignature {
        descriptor: stable_descriptor(&descriptor),
        is_static,
        opcode_skeleton,
        string_constants,
        numeric_constants,
        referenced_descriptors,
        stable_owners,
        stable_member_names,
    })
}

fn harvest_const(
    cf: &ClassFile,
    idx: u16,
    strings: &mut BTreeSet<String>,
    numbers: &mut BTreeSet<i64>,
) {
    let Some(entry): Option<&ConstantPoolEntry> = cf.constant_pool.get(usize::from(idx)) else {
        return;
    };
    match entry {
        ConstantPoolEntry::String { utf8_index } => {
            if let Ok(s) = cf.utf8_at(*utf8_index) {
                strings.insert(s.to_owned());
            }
        }
        ConstantPoolEntry::Integer(v) => {
            numbers.insert(i64::from(*v));
        }
        ConstantPoolEntry::Long(v) => {
            numbers.insert(*v);
        }
        _ => {}
    }
}

fn harvest_ref(
    cf: &ClassFile,
    idx: u16,
    descriptors: &mut BTreeSet<String>,
    stable_owners: &mut BTreeSet<String>,
    stable_member_names: &mut BTreeSet<String>,
) {
    let Some(entry): Option<&ConstantPoolEntry> = cf.constant_pool.get(usize::from(idx)) else {
        return;
    };
    let (class_index, name_and_type_index): (u16, u16) = match entry {
        ConstantPoolEntry::Methodref {
            class_index,
            name_and_type_index,
        }
        | ConstantPoolEntry::Fieldref {
            class_index,
            name_and_type_index,
        }
        | ConstantPoolEntry::InterfaceMethodref {
            class_index,
            name_and_type_index,
        } => (*class_index, *name_and_type_index),
        _ => return,
    };
    let owner: Option<&str> = cf.class_name(class_index).ok();
    let owner_stable: bool = owner.is_some_and(is_stable_type);
    if let (Some(owner_name), true) = (owner, owner_stable) {
        stable_owners.insert(owner_name.to_owned());
    }
    if let Some(ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    }) = cf.constant_pool.get(usize::from(name_and_type_index))
    {
        if let Ok(desc) = cf.utf8_at(*descriptor_index) {
            descriptors.insert(stable_descriptor(desc));
        }
        if owner_stable && let Ok(member) = cf.utf8_at(*name_index) {
            stable_member_names.insert(member.to_owned());
        }
    }
}

fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter: usize = a.intersection(b).count();
    let union: usize = a.union(b).count();
    if union == 0 {
        return 1.0;
    }
    inter as f64 / union as f64
}

fn skeleton_similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let lcs: usize = longest_common_subsequence(a, b);
    let denom: usize = a.len().max(b.len());
    if denom == 0 {
        return 1.0;
    }
    lcs as f64 / denom as f64
}

fn longest_common_subsequence(a: &[u8], b: &[u8]) -> usize {
    let n: usize = b.len();
    let mut prev: Vec<usize> = vec![0; n + 1];
    let mut curr: Vec<usize> = vec![0; n + 1];
    for &av in a {
        for j in 0..n {
            curr[j + 1] = if av == b[j] {
                prev[j] + 1
            } else {
                curr[j].max(prev[j + 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev[n]
}

fn method_score(a: &MethodSignature, b: &MethodSignature) -> f64 {
    if a.is_static != b.is_static {
        return 0.0;
    }
    if a.descriptor != b.descriptor {
        return 0.0;
    }
    let skeleton: f64 = skeleton_similarity(&a.opcode_skeleton, &b.opcode_skeleton);
    let strings: f64 = jaccard(&a.string_constants, &b.string_constants);
    let numbers: f64 = jaccard(&a.numeric_constants, &b.numeric_constants);
    let descriptors: f64 = jaccard(&a.referenced_descriptors, &b.referenced_descriptors);
    let members: f64 = jaccard(&a.stable_member_names, &b.stable_member_names);
    weighted_sum(&[
        (0.55, skeleton),
        (0.15, strings),
        (0.10, numbers),
        (0.10, descriptors),
        (0.10, members),
    ])
}

fn weighted_sum(terms: &[(f64, f64)]) -> f64 {
    terms
        .iter()
        .map(|&(weight, value): &(f64, f64)| weight * value)
        .sum()
}

fn class_score(obf: &ClassSignature, lib: &ClassSignature) -> f64 {
    let super_match: f64 = if obf.stable_super == lib.stable_super {
        1.0
    } else {
        0.0
    };
    let ifaces: f64 = jaccard(&obf.stable_interfaces, &lib.stable_interfaces);
    let fields: f64 = field_shape_similarity(&obf.field_shapes, &lib.field_shapes);
    let strings: f64 = jaccard(&obf.class_strings, &lib.class_strings);
    let numbers: f64 = jaccard(&obf.class_numbers, &lib.class_numbers);
    let body: f64 = aggregate_method_overlap(obf, lib);
    weighted_sum(&[
        (0.10, super_match),
        (0.05, ifaces),
        (0.10, fields),
        (0.25, strings),
        (0.10, numbers),
        (0.40, body),
    ])
}

fn field_shape_similarity(a: &BTreeMap<String, usize>, b: &BTreeMap<String, usize>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let mut inter: usize = 0;
    let mut total: usize = 0;
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for key in keys {
        let av: usize = a.get(key).copied().unwrap_or(0);
        let bv: usize = b.get(key).copied().unwrap_or(0);
        inter += av.min(bv);
        total += av.max(bv);
    }
    if total == 0 {
        return 1.0;
    }
    inter as f64 / total as f64
}

fn aggregate_method_overlap(obf: &ClassSignature, lib: &ClassSignature) -> f64 {
    if obf.methods.is_empty() && lib.methods.is_empty() {
        return 1.0;
    }
    if obf.methods.is_empty() || lib.methods.is_empty() {
        return 0.0;
    }
    let mut matched: f64 = 0.0;
    for om in &obf.methods {
        let best: f64 = lib
            .methods
            .iter()
            .map(|lm: &MethodSignature| method_score(om, lm))
            .fold(0.0_f64, f64::max);
        matched += best;
    }
    let denom: usize = obf.methods.len().max(lib.methods.len());
    matched / denom as f64
}

#[must_use]
pub fn fingerprint(obfuscated: &[ClassFile], library: &LibrarySignatureSet) -> FingerprintReport {
    if library.is_empty() {
        return FingerprintReport::default();
    }
    let mut report: FingerprintReport = FingerprintReport::default();
    let mut claimed: BTreeSet<usize> = BTreeSet::new();
    let obf_sigs: Vec<ClassSignature> = obfuscated.iter().map(signature_for_class).collect();
    let mut ranked: Vec<(usize, usize, f64)> = Vec::new();
    for (oi, obf) in obf_sigs.iter().enumerate() {
        for (li, lib) in library.classes.iter().enumerate() {
            let score: f64 = class_score(obf, lib);
            if score >= MIN_CLASS_SCORE {
                ranked.push((oi, li, score));
            }
        }
    }
    ranked.sort_by(|a: &(usize, usize, f64), b: &(usize, usize, f64)| {
        b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut used_obf: BTreeSet<usize> = BTreeSet::new();
    let mut second_best: BTreeMap<usize, f64> = BTreeMap::new();
    {
        let mut per_obf: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
        for &(oi, _li, score) in &ranked {
            per_obf.entry(oi).or_default().push(score);
        }
        for (oi, mut scores) in per_obf {
            scores
                .sort_by(|a: &f64, b: &f64| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            let runner: f64 = scores.get(1).copied().unwrap_or(0.0);
            second_best.insert(oi, runner);
        }
    }
    for &(oi, li, score) in &ranked {
        if used_obf.contains(&oi) || claimed.contains(&li) {
            continue;
        }
        let runner: f64 = second_best.get(&oi).copied().unwrap_or(0.0);
        if score - runner < MIN_CLASS_MARGIN && runner > 0.0 {
            continue;
        }
        let obf: &ClassSignature = &obf_sigs[oi];
        let lib: &ClassSignature = &library.classes[li];
        let methods: Vec<ReidentifiedMethod> = match_methods(obf, lib);
        let fields: Vec<ReidentifiedField> = match_fields(obfuscated, oi, lib);
        report.classes.push(ReidentifiedClass {
            obfuscated_name: obf.name.clone(),
            original_name: lib.name.clone(),
            score,
            methods,
            fields,
        });
        used_obf.insert(oi);
        claimed.insert(li);
    }
    report
        .classes
        .sort_by(|a: &ReidentifiedClass, b: &ReidentifiedClass| {
            a.obfuscated_name.cmp(&b.obfuscated_name)
        });
    report
}

fn match_methods(obf: &ClassSignature, lib: &ClassSignature) -> Vec<ReidentifiedMethod> {
    let mut out: Vec<ReidentifiedMethod> = Vec::new();
    let mut used_lib: BTreeSet<usize> = BTreeSet::new();
    for (mi, om) in obf.methods.iter().enumerate() {
        let Some(obf_name): Option<&String> = obf.method_names.get(mi) else {
            continue;
        };
        if obf_name == "<init>" || obf_name == "<clinit>" {
            continue;
        }
        let mut best: Option<(usize, f64)> = None;
        for (li, lm) in lib.methods.iter().enumerate() {
            if used_lib.contains(&li) {
                continue;
            }
            if lib
                .method_names
                .get(li)
                .is_some_and(|n: &String| n == "<init>" || n == "<clinit>")
            {
                continue;
            }
            let score: f64 = method_score(om, lm);
            if score >= MIN_METHOD_SCORE && best.is_none_or(|(_, s): (usize, f64)| score > s) {
                best = Some((li, score));
            }
        }
        if let Some((li, score)) = best
            && let Some(lib_method) = lib.method_names.get(li)
        {
            used_lib.insert(li);
            out.push(ReidentifiedMethod {
                obfuscated_name: obf_name.clone(),
                descriptor: om.descriptor.clone(),
                original_name: lib_method.clone(),
                score,
            });
        }
    }
    out
}

fn match_fields(
    obfuscated: &[ClassFile],
    oi: usize,
    lib: &ClassSignature,
) -> Vec<ReidentifiedField> {
    let obf_cf: &ClassFile = &obfuscated[oi];
    let mut out: Vec<ReidentifiedField> = Vec::new();
    let mut used_lib: BTreeSet<usize> = BTreeSet::new();
    for field in &obf_cf.fields {
        let Ok(obf_name): Result<&str, _> = obf_cf.utf8_at(field.name_index) else {
            continue;
        };
        let Ok(desc): Result<&str, _> = obf_cf.utf8_at(field.descriptor_index) else {
            continue;
        };
        let want_static: bool = field.access_flags & ACC_STATIC != 0;
        let want_final: bool = field.access_flags & ACC_FINAL != 0;
        let want_shape: String = stable_descriptor(desc);
        let mut matched: Option<usize> = None;
        let mut match_count: usize = 0;
        for (li, lf) in lib.fields.iter().enumerate() {
            if used_lib.contains(&li) {
                continue;
            }
            if lf.is_static == want_static
                && lf.is_final == want_final
                && stable_descriptor(&lf.descriptor) == want_shape
            {
                match_count += 1;
                if matched.is_none() {
                    matched = Some(li);
                }
            }
        }
        if match_count == 1
            && let Some(li) = matched
            && let Some(name) = lib.field_names.get(li)
        {
            used_lib.insert(li);
            out.push(ReidentifiedField {
                obfuscated_name: obf_name.to_owned(),
                descriptor: desc.to_owned(),
                original_name: name.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_types_recognized() {
        assert!(is_stable_type("java/lang/String"));
        assert!(is_stable_type("Ljava/util/List;"));
        assert!(is_stable_type("[Ljava/lang/Object;"));
        assert!(is_stable_type("kotlin/Unit"));
        assert!(is_stable_type("androidx/core/View"));
        assert!(!is_stable_type("com/acme/Foo"));
        assert!(!is_stable_type("a/a/a/b"));
    }

    #[test]
    fn stable_descriptor_blanks_obfuscated_owner_only() {
        assert_eq!(
            stable_descriptor("(Ljava/lang/String;I)Ljava/lang/String;"),
            "(Ljava/lang/String;I)Ljava/lang/String;"
        );
        assert_eq!(stable_descriptor("(La/a/b;)V"), "(#)V");
        assert_eq!(
            stable_descriptor("(La/a/b;Ljava/lang/String;)La/c;"),
            "(#Ljava/lang/String;)#"
        );
        assert_eq!(stable_descriptor("(II)Z"), "(II)Z");
    }

    #[test]
    fn jaccard_overlap_bounds() {
        let a: BTreeSet<i64> = [1, 2, 3].into_iter().collect();
        let b: BTreeSet<i64> = [2, 3, 4].into_iter().collect();
        let score: f64 = jaccard(&a, &b);
        assert!((score - 0.5).abs() < 1e-9, "got {score}");
        let empty_a: BTreeSet<i64> = BTreeSet::new();
        let empty_b: BTreeSet<i64> = BTreeSet::new();
        assert!((jaccard(&empty_a, &empty_b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn skeleton_similarity_matches_identical_and_drifts_gracefully() {
        let a: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert!((skeleton_similarity(&a, &a) - 1.0).abs() < 1e-9);
        let b: [u8; 5] = [0x01, 0x02, 0x09, 0x04, 0x05];
        let drift: f64 = skeleton_similarity(&a, &b);
        assert!(drift > 0.7 && drift < 1.0, "got {drift}");
        let empty: [u8; 0] = [];
        assert!((skeleton_similarity(&empty, &empty) - 1.0).abs() < 1e-9);
        assert!((skeleton_similarity(&a, &empty)).abs() < 1e-9);
    }

    #[test]
    fn lcs_length_is_correct() {
        assert_eq!(longest_common_subsequence(b"abcde", b"ace"), 3);
        assert_eq!(longest_common_subsequence(b"", b"xyz"), 0);
        assert_eq!(longest_common_subsequence(b"aaa", b"aa"), 2);
    }

    #[test]
    fn method_score_zero_on_descriptor_or_static_mismatch() {
        let base: MethodSignature = MethodSignature {
            descriptor: "(I)V".to_owned(),
            is_static: true,
            opcode_skeleton: vec![0x01, 0x02],
            string_constants: BTreeSet::new(),
            numeric_constants: BTreeSet::new(),
            referenced_descriptors: BTreeSet::new(),
            stable_owners: BTreeSet::new(),
            stable_member_names: BTreeSet::new(),
        };
        let mut other_desc: MethodSignature = base.clone();
        other_desc.descriptor = "(J)V".to_owned();
        assert!((method_score(&base, &other_desc)).abs() < 1e-9);
        let mut other_static: MethodSignature = base.clone();
        other_static.is_static = false;
        assert!((method_score(&base, &other_static)).abs() < 1e-9);
        assert!((method_score(&base, &base) - 1.0).abs() < 1e-9);
    }
}
