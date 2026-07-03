.method System.Int32 KoiSample.Arithmetic::Add(System.Int32,System.Int32)
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: ldarg.1
  IL_0002: add
  IL_0003: ret
}

.method System.Int32 KoiSample.Arithmetic::Square(System.Int32)
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: ldarg.0
  IL_0002: mul
  IL_0003: ret
}

.method System.Int32 KoiSample.Arithmetic::SumTo(System.Int32)
{
  .maxstack 2
  .locals [0] System.Int32
  .locals [1] System.Int32
  IL_0000: ldc.i4.0
  IL_0001: stloc.0
  IL_0002: ldc.i4.1
  IL_0003: stloc.1
  IL_0004: br.s IL_000E: ldloc.1
  IL_0006: ldloc.0
  IL_0007: ldloc.1
  IL_0008: add
  IL_0009: stloc.0
  IL_000A: ldloc.1
  IL_000B: ldc.i4.1
  IL_000C: add
  IL_000D: stloc.1
  IL_000E: ldloc.1
  IL_000F: ldarg.0
  IL_0010: ble.s IL_0006: ldloc.0
  IL_0012: ldloc.0
  IL_0013: ret
}

.method System.Int32 KoiSample.Arithmetic::Classify(System.Int32)
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: ldc.i4.0
  IL_0002: bge.s IL_0006: ldarg.0
  IL_0004: ldc.i4.m1
  IL_0005: ret
  IL_0006: ldarg.0
  IL_0007: brtrue.s IL_000B: ldc.i4.1
  IL_0009: ldc.i4.0
  IL_000A: ret
  IL_000B: ldc.i4.1
  IL_000C: ret
}

.method System.Int64 KoiSample.Arithmetic::Factorial(System.Int32)
{
  .maxstack 2
  .locals [0] System.Int64
  IL_0000: ldc.i4.1
  IL_0001: conv.i8
  IL_0002: stloc.0
  IL_0003: br.s IL_000F: ldarg.0
  IL_0005: ldloc.0
  IL_0006: ldarg.0
  IL_0007: conv.i8
  IL_0008: mul
  IL_0009: stloc.0
  IL_000A: ldarg.0
  IL_000B: ldc.i4.1
  IL_000C: sub
  IL_000D: starg.s n
  IL_000F: ldarg.0
  IL_0010: ldc.i4.1
  IL_0011: bgt.s IL_0005: ldloc.0
  IL_0013: ldloc.0
  IL_0014: ret
}

.method System.Void KoiSample.Counter::.ctor(System.Int32)
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: call System.Void System.Object::.ctor()
  IL_0006: ldarg.0
  IL_0007: ldarg.1
  IL_0008: stfld System.Int32 KoiSample.Counter::count
  IL_000D: ret
}

.method System.Int32 KoiSample.Counter::Increment()
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: ldarg.0
  IL_0002: ldfld System.Int32 KoiSample.Counter::count
  IL_0007: ldc.i4.1
  IL_0008: add
  IL_0009: stfld System.Int32 KoiSample.Counter::count
  IL_000E: ldarg.0
  IL_000F: ldfld System.Int32 KoiSample.Counter::count
  IL_0014: ret
}

.method System.Int32 KoiSample.Counter::Value()
{
  .maxstack 8
  IL_0000: ldarg.0
  IL_0001: ldfld System.Int32 KoiSample.Counter::count
  IL_0006: ret
}

.method System.String KoiSample.Text::Greeting()
{
  .maxstack 8
  IL_0000: ldstr koivm sample
  IL_0005: ret
}

.method System.Int32 KoiSample.Text::Max3(System.Int32,System.Int32,System.Int32)
{
  .maxstack 2
  .locals [0] System.Int32
  IL_0000: ldarg.0
  IL_0001: stloc.0
  IL_0002: ldarg.1
  IL_0003: ldloc.0
  IL_0004: ble.s IL_0008: ldarg.2
  IL_0006: ldarg.1
  IL_0007: stloc.0
  IL_0008: ldarg.2
  IL_0009: ldloc.0
  IL_000A: ble.s IL_000E: ldloc.0
  IL_000C: ldarg.2
  IL_000D: stloc.0
  IL_000E: ldloc.0
  IL_000F: ret
}

.method System.Void KoiSample.Program::Main()
{
  .maxstack 3
  IL_0000: ldc.i4.2
  IL_0001: ldc.i4.3
  IL_0002: call System.Int32 KoiSample.Arithmetic::Add(System.Int32,System.Int32)
  IL_0007: call System.Void System.Console::WriteLine(System.Int32)
  IL_000C: ldc.i4.7
  IL_000D: call System.Int32 KoiSample.Arithmetic::Square(System.Int32)
  IL_0012: call System.Void System.Console::WriteLine(System.Int32)
  IL_0017: ldc.i4.s 10
  IL_0019: call System.Int32 KoiSample.Arithmetic::SumTo(System.Int32)
  IL_001E: call System.Void System.Console::WriteLine(System.Int32)
  IL_0023: ldc.i4.s -5
  IL_0025: call System.Int32 KoiSample.Arithmetic::Classify(System.Int32)
  IL_002A: call System.Void System.Console::WriteLine(System.Int32)
  IL_002F: ldc.i4.5
  IL_0030: call System.Int64 KoiSample.Arithmetic::Factorial(System.Int32)
  IL_0035: call System.Void System.Console::WriteLine(System.Int64)
  IL_003A: ldc.i4.s 40
  IL_003C: newobj System.Void KoiSample.Counter::.ctor(System.Int32)
  IL_0041: call System.Int32 KoiSample.Counter::Increment()
  IL_0046: call System.Void System.Console::WriteLine(System.Int32)
  IL_004B: call System.String KoiSample.Text::Greeting()
  IL_0050: call System.Void System.Console::WriteLine(System.String)
  IL_0055: ldc.i4.3
  IL_0056: ldc.i4.s 9
  IL_0058: ldc.i4.4
  IL_0059: call System.Int32 KoiSample.Text::Max3(System.Int32,System.Int32,System.Int32)
  IL_005E: call System.Void System.Console::WriteLine(System.Int32)
  IL_0063: ret
}

