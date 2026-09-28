pub(crate) const DRUNTIME_DEMANGLE_VECTORS: &[(&str, &str)] = &[
    (r#"printf"#, r#"printf"#),
    (r#"_foo"#, r#"_foo"#),
    (r#"_D88"#, r#"_D88"#),
    (
        r#"_D3fooQeFIAyaZv"#,
        r#"void foo.foo(in immutable(char)[])"#,
    ),
    (
        r#"_D3barQeFIKAyaZv"#,
        r#"void bar.bar(in ref immutable(char)[])"#,
    ),
    (r#"_D4test3fooAa"#, r#"char[] test.foo"#),
    (
        r#"_D8demangle8demangleFAaZAa"#,
        r#"char[] demangle.demangle(char[])"#,
    ),
    (
        r#"_D6object6Object8opEqualsFC6ObjectZi"#,
        r#"int object.Object.opEquals(Object)"#,
    ),
    (r#"_D4test2dgDFiYd"#, r#"double delegate(int, ...) test.dg"#),
    (
        r#"_D4test2dgDxFNfiYd"#,
        r#"double delegate(int, ...) @safe const test.dg"#,
    ),
    (
        r#"_D4test34__T3barVG3uw3_616263VG3wd3_646566Z1xi"#,
        r#"int test.bar!("abc"w, "def"d).x"#,
    ),
    (
        r#"_D8demangle4testFLC6ObjectLDFLiZiZi"#,
        r#"int demangle.test(lazy Object, lazy int delegate(lazy int))"#,
    ),
    (r#"_D8demangle4testFAiXi"#, r#"int demangle.test(int[]...)"#),
    (
        r#"_D8demangle4testFAiYi"#,
        r#"int demangle.test(int[], ...)"#,
    ),
    (
        r#"_D8demangle4testFLAiXi"#,
        r#"int demangle.test(lazy int[]...)"#,
    ),
    (
        r#"_D8demangle4testFLAiYi"#,
        r#"int demangle.test(lazy int[], ...)"#,
    ),
    (
        r#"_D6plugin8generateFiiZAya"#,
        r#"immutable(char)[] plugin.generate(int, int)"#,
    ),
    (
        r#"_D6plugin8generateFiiZAxa"#,
        r#"const(char)[] plugin.generate(int, int)"#,
    ),
    (
        r#"_D6plugin8generateFiiZAOa"#,
        r#"shared(char)[] plugin.generate(int, int)"#,
    ),
    (
        r#"_D8demangle3fnAFZ3fnBMFZv"#,
        r#"void demangle.fnA().fnB()"#,
    ),
    (
        r#"_D8demangle4mainFZ1S3fnCMFZv"#,
        r#"void demangle.main().S.fnC()"#,
    ),
    (
        r#"_D8demangle4mainFZ1S3fnDMFZv"#,
        r#"void demangle.main().S.fnD()"#,
    ),
    (
        r#"_D8demangle20__T2fnVAiA4i1i2i3i4Z2fnFZv"#,
        r#"void demangle.fn!([1, 2, 3, 4]).fn()"#,
    ),
    (
        r#"_D8demangle10__T2fnVi1Z2fnFZv"#,
        r#"void demangle.fn!(1).fn()"#,
    ),
    (
        r#"_D8demangle26__T2fnVS8demangle1SS2i1i2Z2fnFZv"#,
        r#"void demangle.fn!(demangle.S(1, 2)).fn()"#,
    ),
    (
        r#"_D8demangle13__T2fnVeeNANZ2fnFZv"#,
        r#"void demangle.fn!(real.nan).fn()"#,
    ),
    (
        r#"_D8demangle14__T2fnVeeNINFZ2fnFZv"#,
        r#"void demangle.fn!(-real.infinity).fn()"#,
    ),
    (
        r#"_D8demangle13__T2fnVeeINFZ2fnFZv"#,
        r#"void demangle.fn!(real.infinity).fn()"#,
    ),
    (
        r#"_D8demangle21__T2fnVHiiA2i1i2i3i4Z2fnFZv"#,
        r#"void demangle.fn!([1:2, 3:4]).fn()"#,
    ),
    (
        r#"_D8demangle2fnFNgiZNgi"#,
        r#"inout(int) demangle.fn(inout(int))"#,
    ),
    (
        r#"_D8demangle29__T2fnVa97Va9Va0Vu257Vw65537Z2fnFZv"#,
        r#"void demangle.fn!('a', '\t', \x00, '\u0101', '\U00010001').fn()"#,
    ),
    (
        r#"_D2gc11gctemplates56__T8mkBitmapTS3std5range13__T4iotaTiTiZ4iotaFiiZ6ResultZ8mkBitmapFNbNiNfPmmZv"#,
        r#"nothrow @nogc @safe void gc.gctemplates.mkBitmap!(std.range.iota!(int, int).iota(int, int).Result).mkBitmap(ulong*, ulong)"#,
    ),
    (
        r#"_D8serenity9persister6Sqlite69__T15SqlitePersisterTS8serenity9persister6Sqlite11__unittest6FZ4TestZ15SqlitePersister12__T7opIndexZ7opIndexMFmZS8serenity9persister6Sqlite11__unittest6FZ4Test"#,
        r#"serenity.persister.Sqlite.__unittest6().Test serenity.persister.Sqlite.SqlitePersister!(serenity.persister.Sqlite.__unittest6().Test).SqlitePersister.opIndex!().opIndex(ulong)"#,
    ),
    (
        r#"_D8bug100274mainFZ5localMFZi"#,
        r#"int bug10027.main().local()"#,
    ),
    (
        r#"_D8demangle4testFNhG16gZv"#,
        r#"void demangle.test(__vector(byte[16]))"#,
    ),
    (
        r#"_D8demangle4testFNhG8sZv"#,
        r#"void demangle.test(__vector(short[8]))"#,
    ),
    (
        r#"_D8demangle4testFNhG4iZv"#,
        r#"void demangle.test(__vector(int[4]))"#,
    ),
    (
        r#"_D8demangle4testFNhG2lZv"#,
        r#"void demangle.test(__vector(long[2]))"#,
    ),
    (
        r#"_D8demangle4testFNhG4fZv"#,
        r#"void demangle.test(__vector(float[4]))"#,
    ),
    (
        r#"_D8demangle4testFNhG2dZv"#,
        r#"void demangle.test(__vector(double[2]))"#,
    ),
    (
        r#"_D8demangle4testFNhG4fNhG4fZv"#,
        r#"void demangle.test(__vector(float[4]), __vector(float[4]))"#,
    ),
    (
        r#"_D8bug1119234__T3fooS23_D8bug111924mainFZ3bariZ3fooMFZv"#,
        r#"void bug11192.foo!(bug11192.main().bar).foo()"#,
    ),
    (
        r#"_D13libd_demangle12__ModuleInfoZ"#,
        r#"libd_demangle.__ModuleInfo"#,
    ),
    (
        r#"_D15TypeInfo_Struct6__vtblZ"#,
        r#"TypeInfo_Struct.__vtbl"#,
    ),
    (
        r#"_D3std5stdio12__ModuleInfoZ"#,
        r#"std.stdio.__ModuleInfo"#,
    ),
    (
        r#"_D3std6traits15__T8DemangleTkZ8Demangle6__initZ"#,
        r#"std.traits.Demangle!(uint).Demangle.__init"#,
    ),
    (r#"_D3foo3Bar7__ClassZ"#, r#"foo.Bar.__Class"#),
    (r#"_D3foo3Bar6__vtblZ"#, r#"foo.Bar.__vtbl"#),
    (r#"_D3foo3Bar11__interfaceZ"#, r#"foo.Bar.__interface"#),
    (r#"_D3foo7__arrayZ"#, r#"foo.__array"#),
    (
        r#"_D8link657428__T3fooVE8link65746Methodi0Z3fooFZi"#,
        r#"int link6574.foo!(0).foo()"#,
    ),
    (
        r#"_D8link657429__T3fooHVE8link65746Methodi0Z3fooFZi"#,
        r#"int link6574.foo!(0).foo()"#,
    ),
    (
        r#"_D4test22__T4funcVAyaa3_610a62Z4funcFNaNbNiNmNfZAya"#,
        r#"pure nothrow @nogc @live @safe immutable(char)[] test.func!("a\x0ab").func()"#,
    ),
    (r#"_D3foo3barFzkZzi"#, r#"cent foo.bar(ucent)"#),
    (
        r#"_D5bug145Class3fooMFNlZPv"#,
        r#"scope void* bug14.Class.foo()"#,
    ),
    (
        r#"_D5bug145Class3barMFNjZPv"#,
        r#"return void* bug14.Class.bar()"#,
    ),
    (r#"_D5bug143fooFMPvZPv"#, r#"void* bug14.foo(scope void*)"#),
    (
        r#"_D5bug143barFMNkPvZPv"#,
        r#"void* bug14.bar(scope return void*)"#,
    ),
    (
        r#"_D3std5range15__T4iotaTtTtTtZ4iotaFtttZ6Result7opIndexMNgFNaNbNiNfmZNgt"#,
        r#"inout pure nothrow @nogc @safe inout(ushort) std.range.iota!(ushort, ushort, ushort).iota(ushort, ushort, ushort).Result.opIndex(ulong)"#,
    ),
    (
        r#"_D3std6format77__T6getNthVAyaa13_696e7465676572207769647468S233std6traits10isIntegralTiTkTkZ6getNthFNaNfkkkZi"#,
        r#"pure @safe int std.format.getNth!("integer width", std.traits.isIntegral, int, uint, uint).getNth(uint, uint, uint)"#,
    ),
    (
        r#"_D3std11parallelism42__T16RoundRobinBufferTDFKAaZvTDxFNaNdNeZbZ16RoundRobinBuffer5primeMFZv"#,
        r#"void std.parallelism.RoundRobinBuffer!(void delegate(ref char[]), bool delegate() pure @property @trusted const).RoundRobinBuffer.prime()"#,
    ),
    (
        r#"_D6mangle__T8fun21753VSQv6S21753S1f_DQBj10__lambda71MFNaNbNiNfZvZQCbQp"#,
        r#"void function() pure nothrow @nogc @safe mangle.fun21753!(mangle.S21753(mangle.__lambda71())).fun21753"#,
    ),
    (
        r#"_D3std9algorithm9iteration__T9MapResultSQBmQBlQBe005stripTAAyaZQBi7opSliceMFNaNbNiNfmmZSQDiQDhQDa__TQCtSQDyQDxQDq00QCmTQCjZQDq"#,
        r#"pure nothrow @nogc @safe std.algorithm.iteration.MapResult!(std.algorithm.iteration.__anonymous.strip, immutable(char)[][]).MapResult std.algorithm.iteration.MapResult!(std.algorithm.iteration.strip, immutable(char)[][]).MapResult.opSlice(ulong, ulong)"#,
    ),
    (
        r#"_D4core4stdc5errnoQgFZi"#,
        r#"int core.stdc.errno.errno()"#,
    ),
    (
        r#"_D4testFS10structnameQnZb"#,
        r#"bool test(structname, structname)"#,
    ),
    (
        r#"_D3std11parallelism__T4TaskS8unittest3cmpTAyaTQeZQBb6__dtorMFNfZv"#,
        r#"@safe void std.parallelism.Task!(unittest.cmp, immutable(char)[], immutable(char)[]).Task.__dtor()"#,
    ),
    (
        r#"_D13testexpansion44__T1sTS13testexpansion8__T1sTiZ1sFiZ6ResultZ1sFS13testexpansion8__T1sTiZ1sFiZ6ResultZ6Result3fooMFNaNfZv"#,
        r#"pure @safe void testexpansion.s!(testexpansion.s!(int).s(int).Result).s(testexpansion.s!(int).s(int).Result).Result.foo()"#,
    ),
    (
        r#"_D13testexpansion__T1sTSQw__TQjTiZQoFiZ6ResultZQBbFQBcZQq3fooMFNaNfZv"#,
        r#"pure @safe void testexpansion.s!(testexpansion.s!(int).s(int).Result).s(testexpansion.s!(int).s(int).Result).Result.foo()"#,
    ),
    (
        r#"_D3std4conv__T7enumRepTyAaTEQBa12experimental9allocator15building_blocks15stats_collector7OptionsVQCti64ZQDnyQDh"#,
        r#"immutable(char[]) std.conv.enumRep!(immutable(char[]), std.experimental.allocator.building_blocks.stats_collector.Options, 64).enumRep"#,
    ),
    (
        r#"_D3std12experimental9allocator6common__T10reallocateTSQCaQBzQBo15building_blocks17kernighan_ritchie__T8KRRegionTSQEhQEgQDvQCh14null_allocator13NullAllocatorZQCdZQErFNaNbNiKQEpKAvmZb"#,
        r#"pure nothrow @nogc bool std.experimental.allocator.common.reallocate!(std.experimental.allocator.building_blocks.kernighan_ritchie.KRRegion!(std.experimental.allocator.building_blocks.null_allocator.NullAllocator).KRRegion).reallocate(ref std.experimental.allocator.building_blocks.kernighan_ritchie.KRRegion!(std.experimental.allocator.building_blocks.null_allocator.NullAllocator).KRRegion, ref void[], ulong)"#,
    ),
    (
        r#"_D3std9exception__T11doesPointToTASQBh5regex8internal2ir10NamedGroupTQBkTvZQCeFNaNbNiNeKxASQDlQCeQCbQBvQBvKxQtZb"#,
        r#"pure nothrow @nogc @trusted bool std.exception.doesPointTo!(std.regex.internal.ir.NamedGroup[], std.regex.internal.ir.NamedGroup[], void).doesPointTo(ref const(std.regex.internal.ir.NamedGroup[]), ref const(std.regex.internal.ir.NamedGroup[]))"#,
    ),
    (
        r#"_D3std9algorithm9iteration__T14SplitterResultS_DQBu3uni7isWhiteFNaNbNiNfwZbTAyaZQBz9__xtoHashFNbNeKxSQDvQDuQDn__TQDgS_DQEnQCtQCsQCnTQCeZQEdZm"#,
        r#"nothrow @trusted ulong std.algorithm.iteration.SplitterResult!(std.uni.isWhite(dchar), immutable(char)[]).SplitterResult.__xtoHash(ref const(std.algorithm.iteration.SplitterResult!(std.uni.isWhite, immutable(char)[]).SplitterResult))"#,
    ),
    (
        r#"_D3std8typecons__T7TypedefTCQBaQz19__unittestL6513_208FNfZ7MyClassVQBonVAyanZQCh6__ctorMFNaNbNcNiNfQCuZSQDyQDx__TQDrTQDmVQDqnVQCcnZQEj"#,
        r#"pure nothrow ref @nogc @safe std.typecons.Typedef!(std.typecons.__unittestL6513_208().MyClass, null, null).Typedef std.typecons.Typedef!(std.typecons.__unittestL6513_208().MyClass, null, null).Typedef.__ctor(std.typecons.__unittestL6513_208().MyClass)"#,
    ),
    (
        r#"_D3std6getopt__TQkTAyaTDFNaNbNiNfQoZvTQtTDQsZQBnFNfKAQBiQBlQBkQBrQyZSQCpQCo12GetoptResult"#,
        r#"@safe std.getopt.GetoptResult std.getopt.getopt!(immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe, immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe).getopt(ref immutable(char)[][], immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe, immutable(char)[], void delegate(immutable(char)[]) pure nothrow @nogc @safe)"#,
    ),
    (
        r#"_D3std5regex8internal9kickstart__T7ShiftOrTaZQl11ShiftThread__T3setS_DQCqQCpQCmQCg__TQBzTaZQCfQBv10setInvMaskMFNaNbNiNfkkZvZQCjMFNaNfwZv"#,
        r#"pure @safe void std.regex.internal.kickstart.ShiftOr!(char).ShiftOr.ShiftThread.set!(std.regex.internal.kickstart.ShiftOr!(char).ShiftOr.ShiftThread.setInvMask(uint, uint)).set(dchar)"#,
    ),
    (
        r#"_D3std5stdio4File__T8lockImplX10LockFileExTykZQBaMFmmykZi"#,
        r#"int std.stdio.File.lockImpl!(LockFileEx, immutable(uint)).lockImpl(ulong, ulong, immutable(uint))"#,
    ),
    (
        r#"_D3std9algorithm9iteration__T12FilterResultSQBq8typecons__T5TupleTiVAyaa1_61TiVQla1_62TiVQva1_63ZQBm__T6renameVHiQBtA2i0a1_63i2a1_61ZQBeMFNcZ9__lambda1TAiZQEw9__xtoHashFNbNeKxSQGsQGrQGk__TQGdSQHiQFs__TQFmTiVQFja1_61TiVQFua1_62TiVQGfa1_63ZQGx__TQFlVQFhA2i0a1_63i2a1_61ZQGjMFNcZQFfTQEyZQJvZm"#,
        r#"nothrow @trusted ulong std.algorithm.iteration.FilterResult!(std.typecons.Tuple!(int, "a", int, "b", int, "c").Tuple.rename!([0:"c", 2:"a"]).rename().__lambda1, int[]).FilterResult.__xtoHash(ref const(std.algorithm.iteration.FilterResult!(std.typecons.Tuple!(int, "a", int, "b", int, "c").Tuple.rename!([0:"c", 2:"a"]).rename().__lambda1, int[]).FilterResult))"#,
    ),
    (r#"_D4test4rrs1FKPiZv"#, r#"void test.rrs1(ref int*)"#),
    (
        r#"_D4test4rrs1FMNkJPiZv"#,
        r#"void test.rrs1(scope return out int*)"#,
    ),
    (
        r#"_D4test4rrs1FMNkKPiZv"#,
        r#"void test.rrs1(scope return ref int*)"#,
    ),
    (
        r#"_D4test4rrs1FNkJPiZv"#,
        r#"void test.rrs1(return out int*)"#,
    ),
    (
        r#"_D4test4rrs1FNkKPiZv"#,
        r#"void test.rrs1(return ref int*)"#,
    ),
    (
        r#"_D4test4rrs1FNkMJPiZv"#,
        r#"void test.rrs1(return scope out int*)"#,
    ),
    (
        r#"_D4test4rrs1FNkMKPiZv"#,
        r#"void test.rrs1(return scope ref int*)"#,
    ),
    (
        r#"_D4test4rrs1FNkMPiZv"#,
        r#"void test.rrs1(return scope int*)"#,
    ),
    (
        r#"_D3foo3Foo3barMNgFNjNlNfZNgPv"#,
        r#"inout return scope @safe inout(void*) foo.Foo.bar()"#,
    ),
    (
        r#"_D3foo3FooQiMNgFNlNfZv"#,
        r#"inout scope @safe void foo.Foo.foo()"#,
    ),
    (
        r#"_D3foo3Foo4foorMNgFNjNfZv"#,
        r#"inout return @safe void foo.Foo.foor()"#,
    ),
    (
        r#"_D3foo3Foo3rabMNgFNlNjNfZv"#,
        r#"inout scope return @safe void foo.Foo.rab()"#,
    ),
    (
        r#"_D3foo__T1fVdeFA3D0FBFB72A3C33FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"#,
        r#"_D3foo__T1fVdeFA3D0FBFB72A3C33FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"#,
    ),
];
