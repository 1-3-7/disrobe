.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89)
  .ver 4:0:0:0
}
.module extern Sibling.netmodule
.assembly MethodImplShapes
{
  .ver 1:0:0:0
}
.module MethodImplShapes.dll

.class public sequential ansi sealed beforefieldinit MethodImplShapes.ReuseSlotOverride
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.FinalReuseSlotOverride
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public final hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.NewSlotVirtual
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public hidebysig newslot virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.FinalWithoutVirtual
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public final hidebysig instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.MethodDefImplBody
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .override [mscorlib]System.Object::Equals
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.AssemblyRefTypeRefImplBody
       extends [mscorlib]System.ValueType
{
  .override method instance bool [mscorlib]System.Object::Equals(object) with method instance bool [mscorlib]System.Object::Equals(object)
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.ModuleRefTypeRefImplBody
       extends [mscorlib]System.ValueType
{
  .override method instance bool [mscorlib]System.Object::Equals(object) with method instance bool [.module Sibling.netmodule]MethodImplShapes.Foreign::Equals(object)
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.TypeSpecImplBody
       extends [mscorlib]System.ValueType
{
  .override method instance bool [mscorlib]System.Object::Equals(object) with method instance bool valuetype MethodImplShapes.TypeSpecImplBody::Equals(object)
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.UnrelatedImplBody
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
  .method public hidebysig virtual instance int32 GetHashCode() cil managed
  {
    .override [mscorlib]System.Object::GetHashCode
    .maxstack 1
    ldc.i4.0
    ret
  }
}

.class public sequential ansi sealed beforefieldinit MethodImplShapes.AllThreeOverrides
       extends [mscorlib]System.ValueType
{
  .field public int32 Value
  .method public hidebysig virtual instance bool Equals(object obj) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
  .method public hidebysig virtual instance int32 GetHashCode() cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
  .method public hidebysig virtual instance string ToString() cil managed
  {
    .maxstack 1
    ldnull
    ret
  }
}

.class interface public abstract auto ansi MethodImplShapes.IGauge
{
  .method public hidebysig newslot abstract virtual instance int32 Read() cil managed
  {
  }
}

.class public auto ansi beforefieldinit MethodImplShapes.Meter
       extends [mscorlib]System.Object
       implements MethodImplShapes.IGauge
{
  .method private hidebysig newslot virtual final instance int32 'MethodImplShapes.IGauge.Read'() cil managed
  {
    .override MethodImplShapes.IGauge::Read
    .maxstack 1
    ldc.i4.s 42
    ret
  }
  .method public hidebysig specialname rtspecialname instance void .ctor() cil managed
  {
    .maxstack 1
    ldarg.0
    call instance void [mscorlib]System.Object::.ctor()
    ret
  }
}
