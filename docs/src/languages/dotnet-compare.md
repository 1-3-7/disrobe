# .NET build comparison

`disrobe dotnet compare` compares two builds of a .NET assembly without running either. It reports added, removed and changed types, fields, methods, properties, events, P/Invoke imports, assembly references, manifest resources and custom attributes, and the identity of the assembly: version, culture, public key token, MVID and target framework. A changed method body is classified as changed IL or as the same IL with renumbered metadata tokens. Every finding cites the metadata table row it came from in each build.

## Command

```sh
disrobe dotnet compare old/App.dll new/App.dll
disrobe dotnet compare old/App.dll new/App.dll --json
```

The text report prints both assemblies, the number of added, removed and changed findings per entity, and one line per finding:

```text
added method int32 Platform.Native::GetCurrentThreadId() [MethodDef#4]
removed pinvoke int32 Platform.Native::GetCurrentProcessId() [ImplMap#4]
changed pinvoke void Platform.Native::Pause(uint32) entry-point: Sleep -> SleepEx [ImplMap#3 -> ImplMap#3]
changed method int32 Layout.Calc::A(int32) body token-renumbered: 9 bytes -> 9 bytes [MethodDef#2 -> MethodDef#10]
changed identity version: 1.0.0.0 -> 2.1.0.0 [Assembly#1 -> Assembly#1]
```

A line names the change, the entity, its key, the aspect that changed with the old and new value, and the rows in brackets: the old build's row first, then the new build's row. Lines are sorted by their text, so two runs on the same inputs print the same bytes. `--json` prints the same findings as one document with the schema `disrobe.dotnet.build-compare/v1`.

## Entities and aspects

| Entity | Key | Aspects compared |
|---|---|---|
| `identity` | the field name | `name`, `version`, `culture`, `flags`, `hash-algorithm`, `public-key-token`, `security` and `target-framework` from the `Assembly` row and its `TargetFrameworkAttribute`; `module` and `mvid` from the `Module` row; `metadata-version` from the metadata root; `pe-timestamp` and `machine` from the COFF header; `clr-flags` from the CLI header; `reproducible` from a Reproducible entry in the debug directory |
| `assembly-ref` | assembly name | `version`, `culture`, `flags`, `public-key` |
| `type` | full name, nested types as `Outer/Inner` | `flags`, `extends`, `interfaces`, `generic-parameters` with flags and constraints, `layout`, `method-impls`, `security` |
| `field` | `Type::name` | `flags`, `type`, `constant`, `offset`, `marshal` |
| `method` | return type, owner, name, generic arity and parameter types | `signature`, `flags`, `impl-flags`, `parameters` with names, flags, defaults and marshalling, `generic-parameters`, `security`, `body` |
| `property` | the same form as a method | `signature`, `flags`, `accessors`, `constant` |
| `event` | `Type::name` | `flags`, `type`, `accessors` |
| `pinvoke` | the importing method | `module`, `entry-point`, `flags` from the `ImplMap` row |
| `resource` | resource name | `flags`, `implementation` (embedded, a linked file or another assembly), `size` and `sha256` of embedded data |
| `attribute` | the owner and the attribute type | the constructor parameter types and the encoded value |

Types in keys and values use one spelling in both builds: primitives as `int32`, `string` or `native int`; a referenced type as `[System.Runtime]System.Console`; a generic instantiation as ``List`1<int32>``; generic parameters as `!0` and `!!0`; custom modifiers as `int32& modreq([System.Runtime]System.Runtime.InteropServices.InAttribute)`.

## Method bodies

A method present in both builds gets one of three outcomes:

| Outcome | Meaning |
|---|---|
| no finding | The body bytes are identical and every token in them resolves to the same name. |
| `body token-renumbered` | The body bytes differ, but after each metadata token, user string and local signature is replaced by the member, string or type it resolves to, the instructions, exception handlers, locals, `maxstack` and `initlocals` are identical. Reordered declarations and new members elsewhere in the assembly produce this outcome. |
| `body il-changed` | The resolved instructions, handlers or locals differ. This includes a body whose bytes are identical but whose tokens now resolve to a different string or member. |

A body that appears or disappears, for example a method that became `extern`, is `body il-changed` with `none` on one side. Methods whose code type is native or runtime are not decoded.

## Matching rules

Entities match by key. A method or property whose signature changed has a new key; when its owner and name leave exactly one unmatched entry in each build, the two are reported as one `signature` change instead of a removal and an addition. Attributes match by owner, type and value; when one owner and attribute type leave exactly one unmatched attribute in each build, the change is reported as `value`. A renamed member has a different key and appears as one removal and one addition.

The compiler-written pseudo-attributes `Serializable` and `NonSerialized` are flags in metadata and appear as `flags` changes of the type or field.

## Identity and deterministic builds

A deterministic build derives the MVID and the PE timestamp from the content, so any other change also changes both. A build without `-deterministic` writes a random MVID and the current time. Two non-deterministic builds of the same source therefore differ in exactly two findings, `identity mvid` and `identity pe-timestamp`, and in nothing else.

## Refusals

An input that cannot be compared is refused with a typed error instead of a report:

| Code | Refusal |
|---|---|
| `DR-DOTNET-0960` | The input is not a PE image with CLI metadata. The message names the old or new side. |
| `DR-DOTNET-0961` | A table row, heap index, signature, method body, member list or resource is malformed. The message names the row. |
| `DR-DOTNET-0962` | A bound is exceeded: 16 KiB per rendered name, 256 MiB of rendered names or method bodies per assembly, signature nesting of 32, array rank of 64, 64 levels of nested type names, or 1024 debug directory entries. |
| `DR-DOTNET-0963` | An input file cannot be read. |
| `DR-DOTNET-0964` | The JSON report cannot be written. |
| `DR-DOTNET-0965` | An input file exceeds 512 MiB. |

## JSON shape

```json
{
  "schema": "disrobe.dotnet.build-compare/v1",
  "old": { "name": "Platform", "version": "0.0.0.0", "mvid": "e02a1a5e-9b87-4e70-8eaa-e937b7e3b1f4", "types": 2, "methods": 4, "fields": 0 },
  "new": { "name": "Platform", "version": "0.0.0.0", "mvid": "74797976-e3cf-4c34-9955-9d7418be2934", "types": 2, "methods": 4, "fields": 0 },
  "counts": {
    "identity": { "added": 0, "removed": 0, "changed": 2 },
    "method": { "added": 1, "removed": 1, "changed": 0 },
    "pinvoke": { "added": 1, "removed": 1, "changed": 3 }
  },
  "findings": [
    {
      "entity": "pinvoke",
      "change": "changed",
      "key": "void Platform.Native::Pause(uint32)",
      "aspect": "entry-point",
      "old": "Sleep",
      "new": "SleepEx",
      "old_location": "ImplMap#3",
      "new_location": "ImplMap#3"
    }
  ]
}
```

`change` is `added`, `removed` or `changed`. `aspect` is null for additions, removals and identity changes. A location is `Table#row`, or `metadata-root`, `coff-header`, `cli-header` or `debug-directory` for identity fields that live outside the tables.

The library entry point is `disrobe_pass_dotnet::build_compare::compare(&[u8], &[u8])`. It returns a `BuildComparison`, whose `lines()` gives the text lines, or a `CompareError` carrying the codes above.

## Grading

`corpus/dotnet/build-compare` holds ten pairs of assemblies compiled from repository C# sources with the .NET SDK 9.0.318 C# compiler, one pair per change kind: added, removed and renamed members; changed bodies under unchanged signatures; signature changes, including `in` parameters, `init` accessors and `volatile` fields; a declaration reorder that moves only tokens; attribute changes; an assembly version, public key and target framework change from net8.0 to net9.0; P/Invoke changes; resource changes; layout, marshalling, function pointer, array, generic constraint, constant and accessor changes; and one source compiled twice without `-deterministic`. `MANIFEST.toml` records each source, flag set, compiler version and SHA-256.

The reference is a C# program in the corpus that reads both builds of each pair through `System.Reflection.Metadata`, decodes IL with the opcode table of `System.Reflection.Emit.OpCodes`, and prints the expected findings. The test compares disrobe's lines with the reference output exactly for all ten pairs. Changing, dropping or duplicating any expected line turns the grade red. The identical-source pair must report only the MVID and PE timestamp changes, comparing any build with itself must report nothing, and swapping the builds must swap every added and removed count.

## Limits

- Debugging information in a PDB, the initial data of RVA fields, and exported types are not compared.
- Attribute values are compared as encoded bytes, so two encodings of the same value appear as a change.
- A renamed member appears as a removal and an addition.
