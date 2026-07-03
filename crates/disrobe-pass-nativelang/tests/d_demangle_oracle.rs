#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_nativelang::{DemangledSymbol, demangle_d};

const ORACLE: &[(&str, &str)] = &[
    (
        "_D3std3utf10strideImplFNaNeamZk",
        "pure @trusted uint std.utf.strideImpl(char, ulong)",
    ),
    (
        "_D3std3utf12UTFException6__initZ",
        "std.utf.UTFException.__init",
    ),
    (
        "_D3std3utf12UTFException6__vtblZ",
        "std.utf.UTFException.__vtbl",
    ),
    (
        "_D3std3utf__T6strideTAaZQlFNaNfQkZk",
        "pure @safe uint std.utf.stride!(char[]).stride(char[])",
    ),
    (
        "_D3std5stdio__T7writelnTAyaZQnFNfQjZv",
        "@safe void std.stdio.writeln!(immutable(char)[]).writeln(immutable(char)[])",
    ),
    (
        "_D4core10checkedint__T4adduZQgFNaNbNiNfmmKbZm",
        "pure nothrow @nogc @safe ulong core.checkedint.addu!().addu(ulong, ulong, ref bool)",
    ),
    (
        "_D4feat7processFMAiKiJiLiZv",
        "void feat.process(scope int[], ref int, out int, lazy int)",
    ),
    (
        "_D4feat8variadicFiAiXv",
        "void feat.variadic(int, int[]...)",
    ),
    (
        "_D4feat9makeAdderFiZ15__lambda_L3_C45MFNaNbNiNfiZi",
        "pure nothrow @nogc @safe int feat.makeAdder(int).__lambda_L3_C45(int)",
    ),
    (
        "_D4feat9makeAdderFiZDFiZi",
        "int delegate(int) feat.makeAdder(int)",
    ),
    (
        "_D4feat__T3VecTdVmi3ZQl11__xopEqualsMxFKxSQBo__TQBmTdVmi3ZQBwZb",
        "const bool feat.Vec!(double, 3uL).Vec.__xopEquals(ref const(feat.Vec!(double, 3uL).Vec))",
    ),
    (
        "_D4feat__T3VecTdVmi3ZQl6__initZ",
        "feat.Vec!(double, 3uL).Vec.__init",
    ),
    (
        "_D4feat__T3VecTdVmi3ZQl9__xtoHashFNbNeKxSQBn__TQBlTdVmi3ZQBvZm",
        "nothrow @trusted ulong feat.Vec!(double, 3uL).Vec.__xtoHash(ref const(feat.Vec!(double, 3uL).Vec))",
    ),
    (
        "_D4feat__T8identityTAyaZQoFNaNbNiNfQpZQs",
        "pure nothrow @nogc @safe immutable(char)[] feat.identity!(immutable(char)[]).identity(immutable(char)[])",
    ),
    (
        "_D4feat__T8identityTiZQmFNaNbNiNfiZi",
        "pure nothrow @nogc @safe int feat.identity!(int).identity(int)",
    ),
    ("_D5hello7Greeter3fibMFlZl", "long hello.Greeter.fib(long)"),
    (
        "_D5hello7Greeter5greetMFZAya",
        "immutable(char)[] hello.Greeter.greet()",
    ),
    (
        "_D5hello7Greeter6__ctorMFAyaZCQBcQz",
        "hello.Greeter hello.Greeter.__ctor(immutable(char)[])",
    ),
    (
        "_D2rt6dmain212_d_run_main2UAAamPUQgZiZ6runAllMFZv",
        "void rt.dmain2._d_run_main2(char[][], ulong, extern (C) int function(char[][])*).runAll()",
    ),
    (
        "_D2rt6dmain218_d_print_throwableUC6object9ThrowableZ5WSink3getMFZPu",
        "wchar* rt.dmain2._d_print_throwable(object.Throwable).WSink.get()",
    ),
    (
        "_D3std5range10primitives__T9moveFrontTSQBl9algorithm9iteration__T12FilterResultSQDa8bitmanip8BitArray7bitsSetMxFNbNdZ18__lambda_L2661_C26TSQFhQFg__T4iotaTmTxmZQlFmxmZ6ResultZQEfZQFvFNaNbNiQFuZm",
        "pure nothrow @nogc ulong std.range.primitives.moveFront!(std.algorithm.iteration.FilterResult!(std.bitmanip.BitArray.bitsSetconst ().__lambda_L2661_C26, std.range.iota!(ulong, const(ulong)).iota(ulong, const(ulong)).Result).FilterResult).moveFront(std.algorithm.iteration.FilterResult!(std.bitmanip.BitArray.bitsSetconst ().__lambda_L2661_C26, std.range.iota!(ulong, const(ulong)).iota(ulong, const(ulong)).Result).FilterResult)",
    ),
    (
        "_D3std6base64__T10Base64ImplVai45Vai95Vai0Z12decodeLengthFNaNbNiNfImZm",
        "pure nothrow @nogc @safe ulong std.base64.Base64Impl!('-', '_', \\x00).decodeLength(in ulong)",
    ),
    (
        "_D3std4meta__T10aliasSeqOfVSQBa5range__T4iotaTmTmZQkFmmZ6ResultS2i0i2Z4Impl6__initZ",
        "std.meta.aliasSeqOf!(std.range.iota!(ulong, ulong).iota(ulong, ulong).Result(0, 2)).Impl.__init",
    ),
    (
        "_D2rt19sections_elf_shared13scanTLSRangesFNbPS4core8internal9container5array__T5ArrayTSQDhQDh9ThreadDSOZQzMDFNbPvQcZvZv",
        "nothrow void rt.sections_elf_shared.scanTLSRanges(core.internal.container.array.Array!(rt.sections_elf_shared.ThreadDSO).Array*, void delegate(void*, void*) nothrow)",
    ),
];

#[test]
fn d_demangler_matches_real_compiler_demangler() {
    for (mangled, expected) in ORACLE {
        let d: DemangledSymbol = demangle_d(mangled)
            .unwrap_or_else(|| panic!("failed to demangle real ldc2 symbol {mangled}"));
        assert_eq!(
            d.demangled, *expected,
            "demangling of {mangled} disagrees with the ldc2 ddemangle ground truth"
        );
    }
}

#[test]
fn d_demangler_recovers_structured_fields() {
    let fib: DemangledSymbol = demangle_d("_D5hello7Greeter3fibMFlZl").expect("fib");
    assert_eq!(fib.module.as_deref(), Some("hello.Greeter"));
    assert_eq!(fib.name, "fib");
    assert_eq!(fib.params, vec!["long".to_owned()]);

    let process: DemangledSymbol = demangle_d("_D4feat7processFMAiKiJiLiZv").expect("process");
    assert_eq!(process.module.as_deref(), Some("feat"));
    assert_eq!(process.name, "process");
    assert_eq!(
        process.params,
        vec![
            "scope int[]".to_owned(),
            "ref int".to_owned(),
            "out int".to_owned(),
            "lazy int".to_owned(),
        ]
    );

    let adder: DemangledSymbol = demangle_d("_D4feat9makeAdderFiZDFiZi").expect("adder");
    assert_eq!(adder.name, "makeAdder");
    assert_eq!(adder.params, vec!["int".to_owned()]);
    assert!(
        adder.demangled.starts_with("int delegate(int)"),
        "delegate return type must be recovered: {}",
        adder.demangled
    );

    let identity: DemangledSymbol =
        demangle_d("_D4feat__T8identityTiZQmFNaNbNiNfiZi").expect("identity");
    assert_eq!(identity.name, "identity");
    assert_eq!(identity.instantiation.as_deref(), Some("int"));
}

#[test]
fn d_demangler_handles_backreferences() {
    let stride: DemangledSymbol =
        demangle_d("_D3std3utf__T6strideTAaZQlFNaNfQkZk").expect("stride");
    assert_eq!(
        stride.demangled, "pure @safe uint std.utf.stride!(char[]).stride(char[])",
        "the Q back-reference for the char[] parameter must resolve"
    );
    assert_eq!(stride.params, vec!["char[]".to_owned()]);
}
