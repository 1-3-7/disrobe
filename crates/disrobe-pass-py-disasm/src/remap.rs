use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object, PyVersion};
use serde::Serialize;

use crate::opcodes::{UNKNOWN_OPCODE, cache_size, opname};

const MAX_CODE_DEPTH: usize = 64;
const MAX_CODE_OBJECTS: usize = 65_536;
const ENTRY_PREFIX: [&str; 4] = ["MAKE_CELL", "COPY_FREE_VARS", "RETURN_GENERATOR", "POP_TOP"];
const RESUME: &str = "RESUME";
const CACHE: &str = "CACHE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RemapVerdict {
    Standard,
    Remapped,
    Unrecognized,
    NotAssessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemapDetection {
    pub verdict: RemapVerdict,
    pub code_objects: usize,
    pub unknown_opcodes: usize,
    pub misplaced_caches: usize,
    pub missing_resume: usize,
    pub entry_opcode: Option<u8>,
    pub stock_resume_opcode: Option<u8>,
}

impl RemapDetection {
    pub const NAME: &'static str = "cpython-opcode-remap";
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RemapError {
    #[error(
        "DR-PYDIS-0201: opcode-remap recovery reads wordcode CPython (3.6 or later), not {major}.{minor}"
    )]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error(
        "DR-PYDIS-0202: the code object tree exceeds the {MAX_CODE_OBJECTS}-object or {MAX_CODE_DEPTH}-level bound"
    )]
    TooLarge,
    #[error(
        "DR-PYDIS-0203: no code object of the reference matches one in the remapped file (same name, constants, names and length)"
    )]
    NoReference,
    #[error(
        "DR-PYDIS-0204: `{name}` differs from its reference at byte {offset} outside the opcode, so the file is not an opcode permutation"
    )]
    OperandMismatch { name: String, offset: usize },
    #[error(
        "DR-PYDIS-0205: the alignment maps remapped opcode {remapped:#04x} to stock {first:#04x} and {second:#04x}, so it is not a permutation"
    )]
    Conflict { remapped: u8, first: u8, second: u8 },
    #[error(
        "DR-PYDIS-0206: remapped opcodes {opcodes} do not occur in the reference, so their stock meaning is unknown"
    )]
    Uncovered { opcodes: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeRemap {
    version: PyVersion,
    to_stock: [Option<u8>; 256],
    aligned_code_objects: usize,
}

impl OpcodeRemap {
    #[must_use]
    pub const fn version(&self) -> PyVersion {
        self.version
    }

    #[must_use]
    pub const fn aligned_code_objects(&self) -> usize {
        self.aligned_code_objects
    }

    #[must_use]
    pub fn covered_opcodes(&self) -> usize {
        self.to_stock.iter().filter(|slot| slot.is_some()).count()
    }

    #[must_use]
    pub fn stock_opcode(&self, remapped: u8) -> Option<u8> {
        self.to_stock[usize::from(remapped)]
    }

    pub fn apply(&self, code: &CodeObject) -> Result<CodeObject, RemapError> {
        let mut uncovered: BTreeSet<u8> = BTreeSet::new();
        let mut budget: usize = MAX_CODE_OBJECTS;
        let rewritten: CodeObject = self.rewrite(code, 0, &mut budget, &mut uncovered)?;
        if uncovered.is_empty() {
            Ok(rewritten)
        } else {
            Err(RemapError::Uncovered {
                opcodes: uncovered
                    .iter()
                    .map(|op: &u8| format!("{op:#04x}"))
                    .collect::<Vec<String>>()
                    .join(", "),
            })
        }
    }

    fn rewrite(
        &self,
        code: &CodeObject,
        depth: usize,
        budget: &mut usize,
        uncovered: &mut BTreeSet<u8>,
    ) -> Result<CodeObject, RemapError> {
        if depth > MAX_CODE_DEPTH || *budget == 0 {
            return Err(RemapError::TooLarge);
        }
        *budget -= 1;
        let mut out: CodeObject = code.clone();
        for op in out.code.iter_mut().step_by(2) {
            match self.to_stock[usize::from(*op)] {
                Some(stock) => *op = stock,
                None => {
                    uncovered.insert(*op);
                }
            }
        }
        for konst in &mut out.consts {
            if let Object::Code(inner) = konst {
                **inner = self.rewrite(inner, depth + 1, budget, uncovered)?;
            }
        }
        Ok(out)
    }
}

fn collect<'a>(code: &'a CodeObject, out: &mut Vec<&'a CodeObject>) -> Result<(), RemapError> {
    let mut stack: Vec<(&'a CodeObject, usize)> = vec![(code, 0)];
    while let Some((current, depth)) = stack.pop() {
        if depth > MAX_CODE_DEPTH || out.len() >= MAX_CODE_OBJECTS {
            return Err(RemapError::TooLarge);
        }
        out.push(current);
        for konst in current.consts.iter().rev() {
            if let Object::Code(inner) = konst {
                stack.push((inner, depth + 1));
            }
        }
    }
    Ok(())
}

fn plain_entry(code: &CodeObject) -> bool {
    const GENERATOR_LIKE: i32 = 0x20 | 0x80 | 0x100 | 0x200;
    const CELL_OR_FREE: u8 = 0xc0;
    code.flags & GENERATOR_LIKE == 0
        && code
            .localspluskinds
            .iter()
            .all(|kind: &u8| kind & CELL_OR_FREE == 0)
}

fn stock_opcode_named(name: &str, version: PyVersion) -> Option<u8> {
    (0..=u8::MAX).find(|op: &u8| opname(*op, version) == name)
}

#[must_use]
pub fn detect_opcode_remap(code: &CodeObject, version: PyVersion) -> RemapDetection {
    let mut detection: RemapDetection = RemapDetection {
        verdict: RemapVerdict::NotAssessed,
        code_objects: 0,
        unknown_opcodes: 0,
        misplaced_caches: 0,
        missing_resume: 0,
        entry_opcode: None,
        stock_resume_opcode: stock_opcode_named(RESUME, version),
    };
    if version.major != 3 || version.minor < 11 || detection.stock_resume_opcode.is_none() {
        return detection;
    }
    let mut objects: Vec<&CodeObject> = Vec::new();
    if collect(code, &mut objects).is_err() {
        detection.verdict = RemapVerdict::Unrecognized;
        return detection;
    }
    detection.code_objects = objects.len();
    let mut entries: BTreeSet<(u8, u8)> = BTreeSet::new();
    let mut odd_length: bool = false;
    for object in &objects {
        odd_length |= object.code.len() % 2 != 0;
        scan_stock_layout(object, version, &mut detection);
        if plain_entry(object)
            && let [op, arg, ..] = object.code.as_slice()
        {
            entries.insert((*op, *arg));
        }
    }
    let stock_fits: bool = detection.unknown_opcodes == 0
        && detection.misplaced_caches == 0
        && detection.missing_resume == 0;
    let consistent_entry: Option<u8> = match entries.iter().collect::<Vec<&(u8, u8)>>().as_slice() {
        [(op, 0)] => Some(*op),
        _ => None,
    };
    detection.entry_opcode = consistent_entry;
    detection.verdict = if odd_length {
        RemapVerdict::Unrecognized
    } else if stock_fits {
        RemapVerdict::Standard
    } else if consistent_entry.is_some() {
        RemapVerdict::Remapped
    } else {
        RemapVerdict::Unrecognized
    };
    detection
}

fn scan_stock_layout(code: &CodeObject, version: PyVersion, detection: &mut RemapDetection) {
    let units: Vec<(u8, u8)> = code
        .code
        .chunks_exact(2)
        .map(|unit: &[u8]| (unit[0], unit[1]))
        .collect();
    let mut index: usize = 0;
    let mut entry_checked: bool = false;
    while let Some((op, _)) = units.get(index).copied() {
        let name: &str = opname(op, version);
        if name == UNKNOWN_OPCODE {
            detection.unknown_opcodes += 1;
        }
        if !entry_checked && !ENTRY_PREFIX.contains(&name) {
            entry_checked = true;
            if name != RESUME {
                detection.missing_resume += 1;
            }
        }
        let caches: usize = usize::from(cache_size(op, version));
        for slot in 1..=caches {
            let cached: Option<&str> = units
                .get(index + slot)
                .map(|(cache_op, _): &(u8, u8)| opname(*cache_op, version));
            if cached != Some(CACHE) {
                detection.misplaced_caches += 1;
            }
        }
        index += 1 + caches;
    }
}

fn object_text(object: &Object) -> Option<&str> {
    match object {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value),
        _ => None,
    }
}

fn same_shape(left: &CodeObject, right: &CodeObject) -> bool {
    let same_consts: bool = left.consts.len() == right.consts.len()
        && left
            .consts
            .iter()
            .zip(&right.consts)
            .all(|pair: (&Object, &Object)| match pair {
                (Object::Code(a), Object::Code(b)) => a.qualname == b.qualname && a.name == b.name,
                (a, b) => a == b,
            });
    left.code.len() == right.code.len()
        && left.name == right.name
        && left.qualname == right.qualname
        && left.names == right.names
        && left.localsplusnames == right.localsplusnames
        && left.varnames == right.varnames
        && left.argcount == right.argcount
        && left.flags == right.flags
        && same_consts
}

pub fn recover_opcode_remap(
    remapped: &CodeObject,
    reference: &CodeObject,
    version: PyVersion,
) -> Result<OpcodeRemap, RemapError> {
    if !version.is_wordcode() {
        return Err(RemapError::UnsupportedVersion {
            major: version.major,
            minor: version.minor,
        });
    }
    let mut remapped_objects: Vec<&CodeObject> = Vec::new();
    collect(remapped, &mut remapped_objects)?;
    let mut reference_objects: Vec<&CodeObject> = Vec::new();
    collect(reference, &mut reference_objects)?;

    let mut to_stock: [Option<u8>; 256] = [None; 256];
    let mut from_stock: [Option<u8>; 256] = [None; 256];
    let mut aligned: usize = 0;
    let mut used: BTreeSet<usize> = BTreeSet::new();
    for stock in &reference_objects {
        let Some((position, target)) = remapped_objects
            .iter()
            .enumerate()
            .find(|(position, candidate)| !used.contains(position) && same_shape(candidate, stock))
        else {
            continue;
        };
        used.insert(position);
        align(target, stock, &mut to_stock, &mut from_stock)?;
        aligned += 1;
    }
    if aligned == 0 {
        return Err(RemapError::NoReference);
    }
    Ok(OpcodeRemap {
        version,
        to_stock,
        aligned_code_objects: aligned,
    })
}

fn align(
    remapped: &CodeObject,
    stock: &CodeObject,
    to_stock: &mut [Option<u8>; 256],
    from_stock: &mut [Option<u8>; 256],
) -> Result<(), RemapError> {
    for (offset, (got, want)) in remapped
        .code
        .chunks_exact(2)
        .zip(stock.code.chunks_exact(2))
        .enumerate()
    {
        let byte: usize = offset * 2;
        if got[1] != want[1] {
            return Err(RemapError::OperandMismatch {
                name: object_text(&stock.qualname)
                    .or_else(|| object_text(&stock.name))
                    .unwrap_or("<code>")
                    .to_owned(),
                offset: byte + 1,
            });
        }
        let (remapped_op, stock_op): (u8, u8) = (got[0], want[0]);
        if let Some(previous) = to_stock[usize::from(remapped_op)]
            && previous != stock_op
        {
            return Err(RemapError::Conflict {
                remapped: remapped_op,
                first: previous,
                second: stock_op,
            });
        }
        if let Some(previous) = from_stock[usize::from(stock_op)]
            && previous != remapped_op
        {
            return Err(RemapError::Conflict {
                remapped: remapped_op,
                first: stock_op,
                second: stock_op,
            });
        }
        to_stock[usize::from(remapped_op)] = Some(stock_op);
        from_stock[usize::from(stock_op)] = Some(remapped_op);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use disrobe_py_marshal::CodeEra;

    use super::*;

    fn text(value: &str) -> Object {
        Object::ShortAscii {
            value: value.to_owned(),
            interned: false,
        }
    }

    fn stock_module() -> CodeObject {
        let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        code.name = text("<module>");
        code.qualname = text("<module>");
        code.names = vec![text("print")];
        code.consts = vec![text("hi"), Object::None];
        code.code = vec![
            151, 0, 2, 0, 101, 0, 100, 0, 171, 1, 0, 0, 0, 0, 0, 0, 1, 0, 121, 1,
        ];
        code
    }

    fn permuted(code: &CodeObject, swap: &[(u8, u8)]) -> CodeObject {
        let mut out: CodeObject = code.clone();
        for op in out.code.iter_mut().step_by(2) {
            if let Some((_, to)) = swap.iter().find(|(from, _)| from == op) {
                *op = *to;
            }
        }
        out
    }

    const SWAP: [(u8, u8); 7] = [
        (151, 7),
        (2, 151),
        (101, 2),
        (0, 250),
        (100, 101),
        (171, 100),
        (121, 171),
    ];

    #[test]
    fn stock_312_module_is_standard() {
        let detection: RemapDetection = detect_opcode_remap(&stock_module(), PyVersion::PY312);
        assert_eq!(detection.verdict, RemapVerdict::Standard, "{detection:?}");
    }

    #[test]
    fn permuted_module_is_reported_and_recovered_from_its_reference() {
        let stock: CodeObject = stock_module();
        let remapped: CodeObject = permuted(&stock, &SWAP);
        let detection: RemapDetection = detect_opcode_remap(&remapped, PyVersion::PY312);
        assert_eq!(detection.verdict, RemapVerdict::Remapped, "{detection:?}");
        assert_eq!(detection.entry_opcode, Some(7));
        let table: OpcodeRemap =
            recover_opcode_remap(&remapped, &stock, PyVersion::PY312).expect("aligns");
        assert_eq!(table.apply(&remapped).expect("covered"), stock);
        assert_eq!(table.covered_opcodes(), 8);
    }

    #[test]
    fn an_opcode_absent_from_the_reference_is_refused_by_value() {
        let stock: CodeObject = stock_module();
        let table: OpcodeRemap =
            recover_opcode_remap(&permuted(&stock, &SWAP), &stock, PyVersion::PY312)
                .expect("aligns");
        let mut other: CodeObject = permuted(&stock, &SWAP);
        other.code[2] = 9;
        assert_eq!(
            table.apply(&other),
            Err(RemapError::Uncovered {
                opcodes: "0x09".to_owned()
            })
        );
    }

    #[test]
    fn operand_changes_are_not_a_permutation() {
        let stock: CodeObject = stock_module();
        let mut remapped: CodeObject = permuted(&stock, &SWAP);
        remapped.code[3] = 4;
        assert!(matches!(
            recover_opcode_remap(&remapped, &stock, PyVersion::PY312),
            Err(RemapError::OperandMismatch { offset: 3, .. })
        ));
    }

    #[test]
    fn unrelated_reference_is_refused() {
        let stock: CodeObject = stock_module();
        let mut unrelated: CodeObject = stock.clone();
        unrelated.names = vec![text("input")];
        assert_eq!(
            recover_opcode_remap(&permuted(&stock, &SWAP), &unrelated, PyVersion::PY312),
            Err(RemapError::NoReference)
        );
    }

    #[test]
    fn nesting_beyond_the_bound_is_refused_not_recursed() {
        let mut nested: CodeObject = stock_module();
        for _ in 0..=MAX_CODE_DEPTH {
            let mut outer: CodeObject = stock_module();
            outer.consts.push(Object::Code(Box::new(nested)));
            nested = outer;
        }
        assert_eq!(
            detect_opcode_remap(&nested, PyVersion::PY312).verdict,
            RemapVerdict::Unrecognized
        );
        assert_eq!(
            recover_opcode_remap(&nested, &stock_module(), PyVersion::PY312),
            Err(RemapError::TooLarge)
        );
    }

    #[test]
    fn odd_length_bytecode_is_unrecognized() {
        let mut odd: CodeObject = stock_module();
        odd.code.push(0);
        assert_eq!(
            detect_opcode_remap(&odd, PyVersion::PY312).verdict,
            RemapVerdict::Unrecognized
        );
    }

    #[test]
    fn legacy_bytecode_is_not_assessed() {
        let detection: RemapDetection = detect_opcode_remap(&stock_module(), PyVersion::PY310);
        assert_eq!(detection.verdict, RemapVerdict::NotAssessed);
        assert_eq!(
            recover_opcode_remap(&stock_module(), &stock_module(), PyVersion::PY27),
            Err(RemapError::UnsupportedVersion { major: 2, minor: 7 })
        );
    }
}
