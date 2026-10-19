# C# call and span contracts

This authored library contains a method named `System.Fake.Contracts.TryParse`
whose last parameter is `ref int`, and a `ReadOnlySpan<int>` initializer with
three integer values whose byte representations also happen to be valid UTF-8.
The recovered call must preserve `ref`; the span must preserve integer elements.

Build with .NET SDK 9.0.318 targeting .NET 8:

```powershell
dotnet build CsharpContracts.csproj -c Release -o publish --disable-build-servers -p:UseSharedCompilation=false -nodeReuse:false
Copy-Item publish/CsharpContracts.dll CsharpContracts.dll
dotnet run --project reference/Inspect.csproj -c Release --disable-build-servers -p:UseSharedCompilation=false -- CsharpContracts.dll
```

`reference.txt` records the independent `System.Reflection.Metadata` reader's
output. `FakeSystemTryParse` calls MethodDef `06000003`, whose signature ends in
`int&`. `get_IntSpan` loads Field `04000001` and calls MethodSpec `2B000001`, an
instantiation of `RuntimeHelpers.CreateSpan<int>`. The fixture library is read as
metadata and is never invoked.

| File | SHA-256 |
| --- | --- |
| `Contracts.cs` | `3e32386f8f5645fbcc04f7729ea2b9b2db2e93c0211f96762275ac21ee7ab99b` |
| `CsharpContracts.csproj` | `af9599878cf67008b4fcf5dc018bbb6b5365b28a39df7f25e91141fb70156a31` |
| `CsharpContracts.dll` | `eb933dcda52e8525d5e1b9c54ce8a33bdc5b8f43f02c98a07181ac3dad4834e8` |
| `reference.txt` | `d802c50d3c46b325c5522a5723cdf81dfba249668cda5ae454f8cd8a48ab9105` |
