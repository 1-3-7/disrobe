#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;

use disrobe_pass_nuitka::{ConstantsPool, Error, decode_const_file};
use disrobe_pass_pickle::PickleValue;

const MODULE_CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const GLOBAL_CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/__constants.const");
const CONSOLE_CONST: &[u8] = include_bytes!(
    "../../../corpus/python/nuitka/console-disable/hello.build/module.__main__.const"
);
const PYI: &str = include_str!("../../../corpus/python/nuitka/module/hello.pyi");

fn identifiers_from_pyi(pyi: &str) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for line in pyi.lines() {
        let trimmed: &str = line.trim();
        let Some(after_def) = trimmed.strip_prefix("def ") else {
            continue;
        };
        let Some(open) = after_def.find('(') else {
            continue;
        };
        ids.insert(after_def[..open].trim().to_owned());
    }
    ids
}

#[test]
fn module_const_roundtrips_ints_and_strings_with_full_consumption() {
    let pool: ConstantsPool = decode_const_file(MODULE_CONST, "module.hello.const", "hello")
        .expect("decode module.hello.const");

    assert_eq!(
        pool.bytes_consumed,
        MODULE_CONST.len(),
        "full-consumption invariant: every byte of the .const blob must decode"
    );
    assert_eq!(
        pool.stream_count, 19,
        "module.hello.const carries 19 streams"
    );

    let pyi_ids: BTreeSet<String> = identifiers_from_pyi(PYI);
    assert_eq!(
        pyi_ids,
        BTreeSet::from(["fib".to_owned(), "greet".to_owned(), "main".to_owned()]),
        "independent .pyi must declare greet/fib/main"
    );
    for id in &pyi_ids {
        assert!(
            pool.strings.contains(id),
            "recovered pool must contain independent .pyi identifier `{id}`; have {:?}",
            pool.strings
        );
    }
    assert!(
        pool.strings.contains("disrobe"),
        "recovered pool must contain the literal `disrobe` (used in main())"
    );

    for expected_int in [0i64, 1, 2, 20] {
        assert!(
            pool.ints.contains(&expected_int),
            "recovered ints must contain exact value {expected_int}; have {:?}",
            pool.ints
        );
    }
}

#[test]
fn tuples_roundtrip_to_their_decoded_elements() {
    let pool: ConstantsPool = decode_const_file(MODULE_CONST, "module.hello.const", "hello")
        .expect("decode module.hello.const");

    assert!(
        !pool.tuples.is_empty(),
        "module.hello.const stores tuple constants (code-object names/varnames)"
    );

    let mut tuple_strings: BTreeSet<String> = BTreeSet::new();
    let mut tuple_ints: BTreeSet<i64> = BTreeSet::new();
    for tuple in &pool.tuples {
        for element in tuple {
            match element {
                PickleValue::Str(s) | PickleValue::BigInt(s) => {
                    tuple_strings.insert(s.clone());
                }
                PickleValue::Int(i) => {
                    tuple_ints.insert(*i);
                }
                _ => {}
            }
        }
    }

    let varnames_tuple: bool = pool.tuples.iter().any(|tuple: &Vec<PickleValue>| {
        let names: Vec<&str> = tuple
            .iter()
            .filter_map(|v: &PickleValue| match v {
                PickleValue::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        names.contains(&"a") && names.contains(&"b") && names.contains(&"_")
    });
    assert!(
        varnames_tuple,
        "fib's local varnames tuple (a, b, _) must roundtrip element-wise; tuples={:?}",
        pool.tuples
    );

    for s in &tuple_strings {
        assert!(
            pool.strings.contains(s),
            "tuple element string `{s}` must also be flattened into the string pool"
        );
    }
    for i in &tuple_ints {
        assert!(
            pool.ints.contains(i),
            "tuple element int `{i}` must also be flattened into the int pool"
        );
    }
}

#[test]
fn global_and_console_blobs_consume_every_byte() {
    let global: ConstantsPool =
        decode_const_file(GLOBAL_CONST, "__constants.const", "").expect("decode __constants.const");
    assert_eq!(
        global.bytes_consumed,
        GLOBAL_CONST.len(),
        "global pool blob must fully consume"
    );
    assert!(global.strings.contains("__compiled__"));
    assert!(global.strings.contains("__module__"));

    let console: ConstantsPool =
        decode_const_file(CONSOLE_CONST, "module.__main__.const", "__main__")
            .expect("decode module.__main__.const");
    assert_eq!(
        console.bytes_consumed,
        CONSOLE_CONST.len(),
        "console-disable blob must fully consume"
    );
    assert_eq!(console.stream_count, 16);
    for id in ["greet", "fib", "disrobe", "main"] {
        assert!(
            console.strings.contains(id),
            "console blob must roundtrip identifier `{id}`"
        );
    }
}

#[test]
fn trailing_bytes_block_silent_partial_parse() {
    let mut truncated_tail: Vec<u8> = MODULE_CONST.to_vec();
    truncated_tail.extend_from_slice(b"\x00\x00\x00");
    let r: Result<ConstantsPool, Error> =
        decode_const_file(&truncated_tail, "module.hello.const", "hello");
    assert!(
        matches!(
            r,
            Err(Error::ConstTrailingBytes { .. } | Error::ConstPickle(_))
        ),
        "appending undecodable trailing bytes must error, never silently drop them: {r:?}"
    );

    let one_int: &[u8] = b"\x80\x05K\x07.";
    let with_garbage: Vec<u8> = [one_int, b"\xff\xff"].concat();
    let r2: Result<ConstantsPool, Error> = decode_const_file(&with_garbage, "x.const", "x");
    assert!(
        r2.is_err(),
        "a clean stream followed by garbage must not yield a silently-truncated pool: {r2:?}"
    );

    let clean: ConstantsPool = decode_const_file(one_int, "x.const", "x").expect("clean decode");
    assert_eq!(clean.bytes_consumed, one_int.len());
    assert!(clean.ints.contains(&7));
}
