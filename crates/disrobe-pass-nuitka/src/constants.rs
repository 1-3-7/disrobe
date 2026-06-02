use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_pickle::{Disassembly, PickleValue, Session, disassemble};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

fn md5_hex_nuitka_repr(s: &str) -> String {
    let repr: String = format!("'{s}'");
    format!("{:x}", md5::compute(repr.as_bytes()))
}

const MAX_STREAMS_PER_FILE: usize = 1_000_000;
const FLATTEN_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantProvenance {
    pub source_file: String,
    pub blob_name: String,
    pub stream_index: usize,
    pub byte_offset: usize,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantEntry {
    pub provenance: ConstantProvenance,
    pub value: PickleValue,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstantsPool {
    pub entries: Vec<ConstantEntry>,
    pub strings: BTreeSet<String>,
    pub ints: BTreeSet<i64>,
    pub floats: Vec<f64>,
    pub tuples: Vec<Vec<PickleValue>>,
    pub globals: BTreeSet<(String, String)>,
    pub digest_to_string: BTreeMap<String, String>,
    pub bytes_consumed: usize,
    pub stream_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstantsTable {
    pub pools: BTreeMap<String, ConstantsPool>,
    pub all_strings: BTreeSet<String>,
    pub all_ints: BTreeSet<i64>,
}

pub fn decode_const_file(
    bytes: &[u8],
    source_file: &str,
    blob_name: &str,
) -> Result<ConstantsPool> {
    let mut session: Session = Session::new();
    let mut pool: ConstantsPool = ConstantsPool::default();
    let mut cursor: usize = 0usize;

    while cursor < bytes.len() {
        let rest: &[u8] = &bytes[cursor..];
        let dis: Disassembly = disassemble(rest)
            .map_err(|e: disrobe_pass_pickle::Error| Error::ConstPickle(e.to_string()))?;
        let stop_off: usize = dis
            .stop_offset
            .ok_or(Error::ConstStreamNoStop { offset: cursor })?;
        let consumed: usize = stop_off + 1;
        let value: PickleValue = session
            .run(&dis)
            .map_err(|e: disrobe_pass_pickle::Error| Error::ConstPickle(e.to_string()))?;

        let provenance: ConstantProvenance = ConstantProvenance {
            source_file: source_file.to_owned(),
            blob_name: blob_name.to_owned(),
            stream_index: pool.entries.len(),
            byte_offset: cursor,
            byte_len: consumed,
        };

        flatten_into(&value, &mut pool, 0)?;
        pool.entries.push(ConstantEntry { provenance, value });

        cursor += consumed;

        if pool.entries.len() > MAX_STREAMS_PER_FILE {
            return Err(Error::ConstTooManyStreams);
        }
    }

    pool.bytes_consumed = cursor;
    pool.stream_count = pool.entries.len();

    if pool.bytes_consumed != bytes.len() {
        return Err(Error::ConstTrailingBytes {
            consumed: cursor,
            total: bytes.len(),
        });
    }

    Ok(pool)
}

pub fn decode_build_constants(files: &[(String, Vec<u8>, String)]) -> Result<ConstantsTable> {
    let mut table: ConstantsTable = ConstantsTable::default();

    for (source_file, bytes, blob_name) in files {
        let pool: ConstantsPool = decode_const_file(bytes, source_file, blob_name)?;
        for s in &pool.strings {
            table.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            table.all_ints.insert(*i);
        }
        table.pools.insert(source_file.clone(), pool);
    }

    Ok(table)
}

fn flatten_into(value: &PickleValue, pool: &mut ConstantsPool, depth: usize) -> Result<()> {
    if depth > FLATTEN_DEPTH {
        return Err(Error::ConstFlattenDepth);
    }
    let next: usize = depth + 1;
    match value {
        PickleValue::Str(s) | PickleValue::BigInt(s) => {
            let digest: String = md5_hex_nuitka_repr(s);
            pool.digest_to_string.insert(digest, s.clone());
            pool.strings.insert(s.clone());
        }
        PickleValue::Int(i) => {
            pool.ints.insert(*i);
        }
        PickleValue::Float(f) => {
            let bits: u64 = f.to_bits();
            if !pool
                .floats
                .iter()
                .any(|existing: &f64| existing.to_bits() == bits)
            {
                pool.floats.push(*f);
            }
        }
        PickleValue::Tuple(items) => {
            pool.tuples.push(items.clone());
            for item in items {
                flatten_into(item, pool, next)?;
            }
        }
        PickleValue::List(items) | PickleValue::Set(items) | PickleValue::FrozenSet(items) => {
            for item in items {
                flatten_into(item, pool, next)?;
            }
        }
        PickleValue::Dict(pairs) => {
            for (k, v) in pairs {
                flatten_into(k, pool, next)?;
                flatten_into(v, pool, next)?;
            }
        }
        PickleValue::Global { module, name } => {
            pool.globals.insert((module.clone(), name.clone()));
            pool.strings.insert(module.clone());
            pool.strings.insert(name.clone());
        }
        PickleValue::PersId { id } => {
            flatten_into(id, pool, next)?;
        }
        PickleValue::Reduce { callable, args } => {
            flatten_into(callable, pool, next)?;
            flatten_into(args, pool, next)?;
        }
        PickleValue::Object { cls, args, state } => {
            flatten_into(cls, pool, next)?;
            flatten_into(args, pool, next)?;
            if let Some(state_value) = state {
                flatten_into(state_value, pool, next)?;
            }
        }
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Bytes(_)
        | PickleValue::Ext { .. }
        | PickleValue::MemoRef { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MODULE_CONST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");

    #[test]
    fn single_stream_int_consumes_all_bytes() {
        let bytes: &[u8] = b"\x80\x05K\x07.";
        let pool: ConstantsPool = decode_const_file(bytes, "x.const", "x").expect("decode");
        assert_eq!(pool.stream_count, 1);
        assert_eq!(pool.bytes_consumed, bytes.len());
        assert!(pool.ints.contains(&7));
    }

    #[test]
    fn concatenated_streams_with_shared_memo() {
        let module: ConstantsPool =
            decode_const_file(MODULE_CONST, "module.hello.const", "hello").expect("decode");
        assert_eq!(module.bytes_consumed, MODULE_CONST.len());
        assert!(module.strings.contains("greet"));
        assert!(module.strings.contains("fib"));
        assert!(module.strings.contains("disrobe"));
        assert!(
            module
                .globals
                .contains(&("builtins".to_owned(), "str".to_owned()))
        );
    }

    #[test]
    fn stream_lacking_stop_surfaces_pickle_error() {
        let bytes: &[u8] = b"\x80\x05K\x07";
        let r: Result<ConstantsPool> = decode_const_file(bytes, "x.const", "x");
        assert!(matches!(r, Err(Error::ConstPickle(_))));
    }

    #[test]
    fn float_dedup_by_bit_pattern() {
        let bytes: &[u8] = b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00G?\xf0\x00\x00\x00\x00\x00\x00.\x80\x05G?\xf0\x00\x00\x00\x00\x00\x00.";
        let pool: ConstantsPool = decode_const_file(bytes, "x.const", "x").expect("decode");
        assert_eq!(pool.floats.len(), 1);
        assert!((pool.floats[0] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn build_constants_unions_strings_and_ints() {
        let files: Vec<(String, Vec<u8>, String)> = vec![
            (
                "a.const".to_owned(),
                b"\x80\x05\x8c\x03foo\x94.".to_vec(),
                "a".to_owned(),
            ),
            (
                "b.const".to_owned(),
                b"\x80\x05K\x2a.".to_vec(),
                "b".to_owned(),
            ),
        ];
        let table: ConstantsTable = decode_build_constants(&files).expect("decode build");
        assert_eq!(table.pools.len(), 2);
        assert!(table.all_strings.contains("foo"));
        assert!(table.all_ints.contains(&42));
    }
}
