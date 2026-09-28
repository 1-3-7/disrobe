pub(crate) const DRUNTIME_DEMANGLE_VECTORS: &[(&str, &str)] = &[
    ("printf", "printf"),
    ("_foo", "_foo"),
    ("_D88", "_D88"),
    ("_D3fooQeFIAyaZv", "void foo.foo(in immutable(char)[])"),
    ("_D3barQeFIKAyaZv", "void bar.bar(in ref immutable(char)[])"),
    ("_D4test3fooAa", "char[] test.foo"),
    (
        "_D8demangle8demangleFAaZAa",
        "char[] demangle.demangle(char[])",
    ),
    (
        "_D6object6Object8opEqualsFC6ObjectZi",
        "int object.Object.opEquals(Object)",
    ),
    ("_D4test2dgDFiYd", "double delegate(int, ...) test.dg"),
    (
        "_D4test2dgDxFNfiYd",
        "double delegate(int, ...) @safe const test.dg",
    ),
    (
        "_D4test34__T3barVG3uw3_616263VG3wd3_646566Z1xi",
        "int test.bar!(\"abc\"w, \"def\"d).x",
    ),
    (
        "_D8demangle4testFLC6ObjectLDFLiZiZi",
        "int demangle.test(lazy Object, lazy int delegate(lazy int))",
    ),
    ("_D8demangle4testFAiXi", "int demangle.test(int[]...)"),
    ("_D8demangle4testFAiYi", "int demangle.test(int[], ...)"),
    ("_D8demangle4testFLAiXi", "int demangle.test(lazy int[]...)"),
    (
        "_D8demangle4testFLAiYi",
        "int demangle.test(lazy int[], ...)",
    ),
    (
        "_D6plugin8generateFiiZAya",
        "immutable(char)[] plugin.generate(int, int)",
    ),
    (
        "_D6plugin8generateFiiZAxa",
        "const(char)[] plugin.generate(int, int)",
    ),
    (
        "_D6plugin8generateFiiZAOa",
        "shared(char)[] plugin.generate(int, int)",
    ),
    ("_D8demangle3fnAFZ3fnBMFZv", "void demangle.fnA().fnB()"),
    (
        "_D8demangle4mainFZ1S3fnCMFZv",
        "void demangle.main().S.fnC()",
    ),
    (
        "_D8demangle4mainFZ1S3fnDMFZv",
        "void demangle.main().S.fnD()",
    ),
    (
        "_D8demangle20__T2fnVAiA4i1i2i3i4Z2fnFZv",
        "void demangle.fn!([1, 2, 3, 4]).fn()",
    ),
    ("_D8demangle10__T2fnVi1Z2fnFZv", "void demangle.fn!(1).fn()"),
    (
        "_D8demangle26__T2fnVS8demangle1SS2i1i2Z2fnFZv",
        "void demangle.fn!(demangle.S(1, 2)).fn()",
    ),
    (
        "_D8demangle13__T2fnVeeNANZ2fnFZv",
        "void demangle.fn!(real.nan).fn()",
    ),
    (
        "_D8demangle14__T2fnVeeNINFZ2fnFZv",
        "void demangle.fn!(-real.infinity).fn()",
    ),
    (
        "_D8demangle13__T2fnVeeINFZ2fnFZv",
        "void demangle.fn!(real.infinity).fn()",
    ),
    (
        "_D8demangle21__T2fnVHiiA2i1i2i3i4Z2fnFZv",
        "void demangle.fn!([1:2, 3:4]).fn()",
    ),
    (
        "_D8demangle2fnFNgiZNgi",
        "inout(int) demangle.fn(inout(int))",
    ),
    (
        "_D8demangle29__T2fnVa97Va9Va0Vu257Vw65537Z2fnFZv",
        "void demangle.fn!('a', '\\t', \\x00, '\\u0101', '\\U00010001').fn()",
    ),
    (
        "_D2gc11gctemplates56__T8mkBitmapTS3std5range13__T4iotaTiTiZ4iotaFiiZ6ResultZ8mkBitmapFNbNiNfPmmZv",
        "nothrow @nogc @safe void gc.gctemplates.mkBitmap!(std.range.iota!(int, int).iota(int, int).Result).mkBitmap(ulong*, ulong)",
    ),
    (
        "_D8serenity9persister6Sqlite69__T15SqlitePersisterTS8serenity9persister6Sqlite11__unittest6FZ4TestZ15SqlitePersister12__T7opIndexZ7opIndexMFmZS8serenity9persister6Sqlite11__unittest6FZ4Test",
        "serenity.persister.Sqlite.__unittest6().Test serenity.persister.Sqlite.SqlitePersister!(serenity.persister.Sqlite.__unittest6().Test).SqlitePersister.opIndex!().opIndex(ulong)",
    ),
    (
        "_D8bug100274mainFZ5localMFZi",
        "int bug10027.main().local()",
    ),
    (
        "_D8demangle4testFNhG16gZv",
        "void demangle.test(__vector(byte[16]))",
    ),
    (
        "_D8demangle4testFNhG8sZv",
        "void demangle.test(__vector(short[8]))",
    ),
    (
        "_D8demangle4testFNhG4iZv",
        "void demangle.test(__vector(int[4]))",
    ),
    (
        "_D8demangle4testFNhG2lZv",
        "void demangle.test(__vector(long[2]))",
    ),
    (
        "_D8demangle4testFNhG4fZv",
        "void demangle.test(__vector(float[4]))",
    ),
    (
        "_D8demangle4testFNhG2dZv",
        "void demangle.test(__vector(double[2]))",
    ),
    (
        "_D8demangle4testFNhG4fNhG4fZv",
        "void demangle.test(__vector(float[4]), __vector(float[4]))",
    ),
    (
        "_D8bug1119234__T3fooS23_D8bug111924mainFZ3bariZ3fooMFZv",
        "void bug11192.foo!(bug11192.main().bar).foo()",
    ),
    (
        "_D13libd_demangle12__ModuleInfoZ",
        "libd_demangle.__ModuleInfo",
    ),
    ("_D15TypeInfo_Struct6__vtblZ", "TypeInfo_Struct.__vtbl"),
    ("_D3std5stdio12__ModuleInfoZ", "std.stdio.__ModuleInfo"),
    (
        "_D3std6traits15__T8DemangleTkZ8Demangle6__initZ",
        "std.traits.Demangle!(uint).Demangle.__init",
    ),
    ("_D3foo3Bar7__ClassZ", "foo.Bar.__Class"),
    ("_D3foo3Bar6__vtblZ", "foo.Bar.__vtbl"),
    ("_D3foo3Bar11__interfaceZ", "foo.Bar.__interface"),
    ("_D3foo7__arrayZ", "foo.__array"),
    (
        "_D8link657428__T3fooVE8link65746Methodi0Z3fooFZi",
        "int link6574.foo!(0).foo()",
    ),
    (
        "_D8link657429__T3fooHVE8link65746Methodi0Z3fooFZi",
        "int link6574.foo!(0).foo()",
    ),
    (
        "_D4test22__T4funcVAyaa3_610a62Z4funcFNaNbNiNmNfZAya",
        "pure nothrow @nogc @live @safe immutable(char)[] test.func!(\"a\\x0ab\").func()",
    ),
    ("_D3foo3barFzkZzi", "cent foo.bar(ucent)"),
    ("_D5bug145Class3fooMFNlZPv", "scope void* bug14.Class.foo()"),
    (
        "_D5bug145Class3barMFNjZPv",
        "return void* bug14.Class.bar()",
    ),
    ("_D5bug143fooFMPvZPv", "void* bug14.foo(scope void*)"),
    (
        "_D5bug143barFMNkPvZPv",
        "void* bug14.bar(scope return void*)",
    ),
    (
        "_D3std5range15__T4iotaTtTtTtZ4iotaFtttZ6Result7opIndexMNgFNaNbNiNfmZNgt",
        "inout pure nothrow @nogc @safe inout(ushort) std.range.iota!(ushort, ushort, ushort).iota(ushort, ushort, ushort).Result.opIndex(ulong)",
    ),
    (
        "_D3std6format77__T6getNthVAyaa13_696e7465676572207769647468S233std6traits10isIntegralTiTkTkZ6getNthFNaNfkkkZi",
        "pure @safe int std.format.getNth!(\"integer width\", std.traits.isIntegral, int, uint, uint).getNth(uint, uint, uint)",
    ),
    (
        "_D3std11parallelism42__T16RoundRobinBufferTDFKAaZvTDxFNaNdNeZbZ16RoundRobinBuffer5primeMFZv",
        "void std.parallelism.RoundRobinBuffer!(void delegate(ref char[]), bool delegate() pure @property @trusted const).RoundRobinBuffer.prime()",
    ),
    (
        "_D6mangle__T8fun21753VSQv6S21753S1f_DQBj10__lambda71MFNaNbNiNfZvZQCbQp",
        "void function() pure nothrow @nogc @safe mangle.fun21753!(mangle.S21753(mangle.__lambda71())).fun21753",
    ),
    (
        "_D3std9algorithm9iteration__T9MapResultSQBmQBlQBe005stripTAAyaZQBi7opSliceMFNaNbNiNfmmZSQDiQDhQDa__TQCtSQDyQDxQDq00QCmTQCjZQDq",
        "pure nothrow @nogc @safe std.algorithm.iteration.MapResult!(std.algorithm.iteration.__anonymous.strip, immutable(char)[][]).MapResult std.algorithm.iteration.MapResult!(std.algorithm.iteration.strip, immutable(char)[][]).MapResult.opSlice(ulong, ulong)",
    ),
    ("_D4core4stdc5errnoQgFZi", "int core.stdc.errno.errno()"),
    (
        "_D4testFS10structnameQnZb",
        "bool test(structname, structname)",
    ),
    (
        "_D3std11parallelism__T4TaskS8unittest3cmpTAyaTQeZQBb6__dtorMFNfZv",
        "@safe void std.parallelism.Task!(unittest.cmp, immutable(char)[], immutable(char)[]).Task.__dtor()",
    ),
    (
        "_D13testexpansion44__T1sTS13testexpansion8__T1sTiZ1sFiZ6ResultZ1sFS13testexpansion8__T1sTiZ1sFiZ6ResultZ6Result3fooMFNaNfZv",
        "pure @safe void testexpansion.s!(testexpansion.s!(int).s(int).Result).s(testexpansion.s!(int).s(int).Result).Result.foo()",
    ),
    (
        "_D13testexpansion__T1sTSQw__TQjTiZQoFiZ6ResultZQBbFQBcZQq3fooMFNaNfZv",
        "pure @safe void testexpansion.s!(testexpansion.s!(int).s(int).Result).s(testexpansion.s!(int).s(int).Result).Result.foo()",
    ),
    (
        "_D3std4conv__T7enumRepTyAaTEQBa12experimental9allocator15building_blocks15stats_collector7OptionsVQCti64ZQDnyQDh",
        "immutable(char[]) std.conv.enumRep!(immutable(char[]), std.experimental.allocator.building_blocks.stats_collector.Options, 64).enumRep",
    ),
    (
        "_D3std12experimental9allocator6common__T10reallocateTSQCaQBzQBo15building_blocks17kernighan_ritchie__T8KRRegionTSQEhQEgQDvQCh14null_allocator13NullAllocatorZQCdZQErFNaNbNiKQEpKAvmZb",
        "pure nothrow @nogc bool std.experimental.allocator.common.reallocate!(std.experimental.allocator.building_blocks.kernighan_ritchie.KRRegion!(std.experimental.allocator.building_blocks.null_allocator.NullAllocator).KRRegion).reallocate(ref std.experimental.allocator.building_blocks.kernighan_ritchie.KRRegion!(std.experimental.allocator.building_blocks.null_allocator.NullAllocator).KRRegion, ref void[], ulong)",
    ),
    (
        "_D3std9exception__T11doesPointToTASQBh5regex8internal2ir10NamedGroupTQBkTvZQCeFNaNbNiNeKxASQDlQCeQCbQBvQBvKxQtZb",
        "pure nothrow @nogc @trusted bool std.exception.doesPointTo!(std.regex.internal.ir.NamedGroup[], std.regex.internal.ir.NamedGroup[], void).doesPointTo(ref const(std.regex.internal.ir.NamedGroup[]), ref const(std.regex.internal.ir.NamedGroup[]))",
    ),
    (
        "_D3std9algorithm9iteration__T14SplitterResultS_DQBu3uni7isWhiteFNaNbNiNfwZbTAyaZQBz9__xtoHashFNbNeKxSQDvQDuQDn__TQDgS_DQEnQCtQCsQCnTQCeZQEdZm",
        "nothrow @trusted ulong std.algorithm.iteration.SplitterResult!(std.uni.isWhite(dchar), immutable(char)[]).SplitterResult.__xtoHash(ref const(std.algorithm.iteration.SplitterResult!(std.uni.isWhite, immutable(char)[]).SplitterResult))",
    ),
    (
        "_D3std8typecons__T7TypedefTCQBaQz19__unittestL6513_208FNfZ7MyClassVQBonVAyanZQCh6__ctorMFNaNbNcNiNfQCuZSQDyQDx__TQDrTQDmVQDqnVQCcnZQEj",
        "pure nothrow ref @nogc @safe std.typecons.Typedef!(std.typecons.__unittestL6513_208().MyClass, null, null).Typedef std.typecons.Typedef!(std.typecons.__unittestL6513_208().MyClass, null, null).Typedef.__ctor(std.typecons.__unittestL6513_208().MyClass)",
    ),
    (
        "_D3std6getopt__TQkTAyaTDFNaNbNiNfQoZvTQtTDQsZQBnFNfKAQBiQBlQBkQBrQyZSQCpQCo12GetoptResult",
        "@safe std.getopt.GetoptResult std.getopt.getopt!(immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe, immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe).getopt(ref immutable(char)[][], immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe, immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe)",
    ),
    (
        "_D3std5regex8internal9kickstart__T7ShiftOrTaZQl11ShiftThread__T3setS_DQCqQCpQCmQCg__TQBzTaZQCfQBv10setInvMaskMFNaNbNiNfkkZvZQCjMFNaNfwZv",
        "pure @safe void std.regex.internal.kickstart.ShiftOr!(char).ShiftOr.ShiftThread.set!(std.regex.internal.kickstart.ShiftOr!(char).ShiftOr.ShiftThread.setInvMask(uint, uint)).set(dchar)",
    ),
    (
        "_D3std5stdio4File__T8lockImplX10LockFileExTykZQBaMFmmykZi",
        "int std.stdio.File.lockImpl!(LockFileEx, immutable(uint)).lockImpl(ulong, ulong, immutable(uint))",
    ),
    (
        "_D3std9algorithm9iteration__T12FilterResultSQBq8typecons__T5TupleTiVAyaa1_61TiVQla1_62TiVQva1_63ZQBm__T6renameVHiQBtA2i0a1_63i2a1_61ZQBeMFNcZ9__lambda1TAiZQEw9__xtoHashFNbNeKxSQGsQGrQGk__TQGdSQHiQFs__TQFmTiVQFja1_61TiVQFua1_62TiVQGfa1_63ZQGx__TQFlVQFhA2i0a1_63i2a1_61ZQGjMFNcZQFfTQEyZQJvZm",
        "nothrow @trusted ulong std.algorithm.iteration.FilterResult!(std.typecons.Tuple!(int, \"a\", int, \"b\", int, \"c\").Tuple.rename!([0:\"c\", 2:\"a\"]).rename().__lambda1, int[]).FilterResult.__xtoHash(ref const(std.algorithm.iteration.FilterResult!(std.typecons.Tuple!(int, \"a\", int, \"b\", int, \"c\").Tuple.rename!([0:\"c\", 2:\"a\"]).rename().__lambda1, int[]).FilterResult))",
    ),
    ("_D4test4rrs1FKPiZv", "void test.rrs1(ref int*)"),
    (
        "_D4test4rrs1FMNkJPiZv",
        "void test.rrs1(scope return out int*)",
    ),
    (
        "_D4test4rrs1FMNkKPiZv",
        "void test.rrs1(scope return ref int*)",
    ),
    ("_D4test4rrs1FNkJPiZv", "void test.rrs1(return out int*)"),
    ("_D4test4rrs1FNkKPiZv", "void test.rrs1(return ref int*)"),
    (
        "_D4test4rrs1FNkMJPiZv",
        "void test.rrs1(return scope out int*)",
    ),
    (
        "_D4test4rrs1FNkMKPiZv",
        "void test.rrs1(return scope ref int*)",
    ),
    ("_D4test4rrs1FNkMPiZv", "void test.rrs1(return scope int*)"),
    (
        "_D3foo3Foo3barMNgFNjNlNfZNgPv",
        "inout return scope @safe inout(void*) foo.Foo.bar()",
    ),
    (
        "_D3foo3FooQiMNgFNlNfZv",
        "inout scope @safe void foo.Foo.foo()",
    ),
    (
        "_D3foo3Foo4foorMNgFNjNfZv",
        "inout return @safe void foo.Foo.foor()",
    ),
    (
        "_D3foo3Foo3rabMNgFNlNjNfZv",
        "inout scope return @safe void foo.Foo.rab()",
    ),
    (
        "_D3foo__T1fVdeFA3D0FBFB72A3C33FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "_D3foo__T1fVdeFA3D0FBFB72A3C33FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ),
];
