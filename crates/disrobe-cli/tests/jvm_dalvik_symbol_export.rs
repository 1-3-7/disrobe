#![cfg(feature = "jvm")]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::{Run, run_disrobe, temp_dir};
use disrobe_pass_native::backend_export::{
    DalvikSymbolKey, ExportSymbol, SYMBOL_EXPORT_SCHEMA, SymbolClass, SymbolExport, SymbolKey,
    SymbolOrigin, render_ghidra_postscript, render_idapython, render_symbol_map_json,
};

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture_path() -> PathBuf {
    workspace_root().join("corpus/jvm/dex/EdgeCases.dex")
}

fn run_jvm_export(format: &str) -> (disrobe_core::scratch::ScratchDir, Run, PathBuf) {
    let fixture: PathBuf = fixture_path();
    assert!(
        fixture.exists(),
        "the tracked DEX fixture is required at {}",
        fixture.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dalvik-symbol-export");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let output_arg: String = scratch.path().to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "jvm",
        "decompile",
        &fixture_arg,
        "--out",
        &output_arg,
        "--format",
        format,
    ]);
    let extension: &str = match format {
        "ghidra" => "ghidra.java",
        "ida" => "ida.py",
        "json" => "symbols.json",
        _ => panic!("unexpected format {format}"),
    };
    let sidecar: PathBuf = scratch.path().join(format!("EdgeCases.{extension}"));
    (scratch, run, sidecar)
}

fn parse_java(source: &str) {
    let available: Output = Command::new("javac")
        .arg("-version")
        .output()
        .expect("javac is required to parse generated Ghidra Java scripts");
    assert!(available.status.success(), "javac -version must succeed");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dalvik-java-parse");
    let script_path: PathBuf = scratch.path().join("DisrobeApplySymbols.java");
    let parser_path: PathBuf = scratch.path().join("ParseOnly.java");
    std::fs::write(&script_path, source.as_bytes()).expect("write generated Ghidra script");
    std::fs::write(
        &parser_path,
        b"import com.sun.source.util.JavacTask;\nimport java.io.File;\nimport java.nio.charset.StandardCharsets;\nimport java.util.List;\nimport javax.tools.JavaCompiler;\nimport javax.tools.JavaFileObject;\nimport javax.tools.StandardJavaFileManager;\nimport javax.tools.ToolProvider;\npublic class ParseOnly {\n    public static void main(String[] args) throws Exception {\n        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();\n        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {\n            Iterable<? extends JavaFileObject> units = manager.getJavaFileObjects(new File(args[0]));\n            JavacTask task = (JavacTask) compiler.getTask(null, manager, null, List.of(\"-proc:none\"), null, units);\n            task.parse();\n        }\n    }\n}\n",
    )
    .expect("write Java parser driver");
    let compile: Output = Command::new("javac")
        .arg("-encoding")
        .arg("UTF-8")
        .arg(&parser_path)
        .output()
        .expect("compile Java parser driver");
    assert!(
        compile.status.success(),
        "Java parser driver did not compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let parse: Output = Command::new("java")
        .arg("-cp")
        .arg(scratch.path())
        .arg("ParseOnly")
        .arg(&script_path)
        .output()
        .expect("parse generated Ghidra script");
    assert!(
        parse.status.success(),
        "generated Ghidra script did not parse: {}",
        String::from_utf8_lossy(&parse.stderr)
    );
}

fn compile_python(source: &str) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dalvik-python-compile");
    let script_path: PathBuf = scratch.path().join("symbols.py");
    std::fs::write(&script_path, source.as_bytes()).expect("write generated IDAPython script");
    let compile: Output = Command::new("python")
        .arg("-m")
        .arg("py_compile")
        .arg(&script_path)
        .output()
        .expect("compile generated IDAPython script");
    assert!(
        compile.status.success(),
        "generated IDAPython script did not compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
}

fn execute_ida_dalvik_mutations(source: &str) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dalvik-ida-semantics");
    let script_path: PathBuf = scratch.path().join("symbols.py");
    let harness_path: PathBuf = scratch.path().join("execute_symbols.py");
    std::fs::write(&script_path, source.as_bytes()).expect("write generated IDAPython script");
    std::fs::write(
        &harness_path,
        r#"from __future__ import annotations

import sys
import types
from pathlib import Path


def fake_module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


idaapi = fake_module("idaapi")
idc = fake_module("idc")
ida_funcs = fake_module("ida_funcs")
ida_name = fake_module("ida_name")
ida_entry = fake_module("ida_entry")
ida_bytes = fake_module("ida_bytes")
ida_idaapi = fake_module("ida_idaapi")
ida_netnode = fake_module("ida_netnode")
ida_segment = fake_module("ida_segment")
idadex = fake_module("idadex")

idaapi.get_imagebase = lambda: 0
idc.here = lambda: 0
ida_funcs.get_func = lambda address: None
ida_entry.add_entry = lambda *args: True
ida_idaapi.BADADDR = -1
ida_netnode.BADNODE = -1

names: dict[int, str] = {}
collision_mode = False


def set_name(address: int, replacement: str, flags: int) -> bool:
    names[address] = replacement + "_1" if collision_mode else replacement
    return True


ida_name.SN_NOCHECK = 1
ida_name.SN_FORCE = 2
ida_name.SN_NON_AUTO = 4
ida_name.set_name = set_name
ida_name.get_name = lambda address: names.get(address, "")


class Segment:
    start_ea = 0x2000
    end_ea = 0x2010


ida_segment.get_segment_ea_by_name = lambda name: 0x2000 if name == "TYPES" else -1
ida_segment.getseg = lambda address: Segment() if address == 0x2000 else None

descriptors = {
    0: "Lobfuscated/Original;",
    1: "Lquoted/Owner;",
    2: "Ljava/lang/String;",
    3: "I",
    4: "b",
}
ida_bytes.get_dword = lambda address: (address - 0x2000) // 4


class Node:
    def __init__(self) -> None:
        self.blob: bytes | None = None

    def supfirst(self, tag: int) -> int:
        return 0 if tag in (Dex.DEXVAR_METHOD, Dex.DEXVAR_FIELD) else ida_netnode.BADNODE

    def supnext(self, index: int, tag: int) -> int:
        return ida_netnode.BADNODE

    def setblob(self, payload: bytes, index: int, tag: int) -> bool:
        self.blob = payload
        return True


class Dex:
    DEXVAR_METHOD = 1
    DEXVAR_METH_STRO = 2
    DEXVAR_FIELD = 3
    DEXVAR_TYPE_RENS = 4
    last: Dex | None = None

    def __init__(self) -> None:
        self.nn_vars = [Node()]
        self.baseaddrs = [0x1000]
        self.type_renames = [{}]
        Dex.last = self

    def get_string(self, from_ea: int, index: int) -> str | None:
        return descriptors.get(index)

    @staticmethod
    def get_string_by_index(node: Node, index: int, tag: int) -> str:
        return "a"

    def get_method(self, from_ea: int, index: int) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            cname=1,
            nparams=2,
            proto_params=[2, 3],
            proto_ret=3,
            startAddr=0x3000,
        )

    def get_field(self, from_ea: int, index: int) -> types.SimpleNamespace:
        return types.SimpleNamespace(ctype=1, name=4, type=2, maddr=0x4000)


idadex.Dex = Dex
source = Path(sys.argv[1]).read_text(encoding="utf-8")
scope: dict[str, object] = {"__name__": "__main__"}
exec(compile(source, sys.argv[1], "exec"), scope)

instance = Dex.last
assert instance is not None
assert instance.type_renames[0] == {0: "Lrecovered/pkg/Renamed;"}
assert instance.nn_vars[0].blob is not None
assert names[0x2000] == "Renamed"
assert names[0x3000] == "recoveredMethod"
assert names[0x4000] == "recoveredField"

collision_mode = True
try:
    scope["_dalvik_set_name"](0x5000, "collision")
except RuntimeError as error:
    assert "changed recovered DEX name" in str(error)
else:
    raise AssertionError("silent IDA collision suffix was accepted")
collision_mode = False

type_rename_tag = Dex.DEXVAR_TYPE_RENS
delattr(Dex, "DEXVAR_TYPE_RENS")
try:
    exec(compile(source, sys.argv[1], "exec"), {"__name__": "__main__"})
except RuntimeError as error:
    assert "IDA 9.4 or later" in str(error)
else:
    raise AssertionError("legacy IDA type-rename API was accepted")
finally:
    Dex.DEXVAR_TYPE_RENS = type_rename_tag
"#,
    )
    .expect("write IDA semantic harness");
    let execute: Output = Command::new("python")
        .arg(&harness_path)
        .arg(&script_path)
        .output()
        .expect("execute IDA semantic harness");
    assert!(
        execute.status.success(),
        "IDA semantic harness rejected database mutations: {}",
        String::from_utf8_lossy(&execute.stderr)
    );
}

fn execute_ghidra_dalvik_mutations(source: &str) {
    let helper_start: usize = source
        .find("    private String dalvikType")
        .expect("generated Ghidra script must contain Dalvik helpers");
    let helper_end: usize = source
        .rfind("\n}")
        .expect("generated Ghidra script must close its class");
    let helpers: &str = &source[helper_start..helper_end];
    let mut harness: String = String::from(
        r"import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class DalvikMutationHarness {
    private final FakeHeader header;
    private final FakeProgram currentProgram;
    private final Map<Long, Function> functions;

    private DalvikMutationHarness() {
        header = new FakeHeader();
        currentProgram = new FakeProgram(0x1000L);
        functions = new HashMap<>();
    }

    private Function getFunctionAt(Address address) {
        return functions.get(address.value);
    }

    private void createLabel(Address address, String name, boolean primary, SourceType source) {
        currentProgram.symbols.labels.put(address.value, new Symbol(name, null));
    }

",
    );
    harness.push_str(helpers);
    harness.push_str(
        r#"
    private static void require(boolean condition, String detail) {
        if (!condition) {
            throw new IllegalStateException(detail);
        }
    }

    public static void main(String[] args) throws Exception {
        DalvikMutationHarness test = new DalvikMutationHarness();
        test.header.types.add("Lobfuscated/Original;");
        test.header.types.add("Lquoted/Owner;");
        test.header.types.add("Ljava/lang/String;");
        test.header.types.add("I");
        test.header.strings.add("a");
        test.header.strings.add("unused");
        test.header.strings.add("b");
        test.header.prototypes.add(new PrototypesIDItem(
            List.of(new TypeItem(2), new TypeItem(3)),
            3
        ));
        test.header.methods.add(new MethodIDItem(1, 0, 0));
        test.header.fields.add(new FieldIDItem(1, 3, 1));
        test.header.fields.add(new FieldIDItem(1, 2, 2));

        Namespace obfuscated = test.currentProgram.symbols.getOrCreateNameSpace(
            test.currentProgram.global,
            "obfuscated",
            SourceType.IMPORTED
        );
        test.currentProgram.symbols.getOrCreateNameSpace(
            obfuscated,
            "Original",
            SourceType.IMPORTED
        );
        Namespace quoted = test.currentProgram.symbols.getOrCreateNameSpace(
            test.currentProgram.global,
            "quoted",
            SourceType.IMPORTED
        );
        test.currentProgram.symbols.getOrCreateNameSpace(
            quoted,
            "Owner",
            SourceType.IMPORTED
        );
        test.functions.put(0x2222L, new Function("a"));
        test.currentProgram.equates.byValue.put(
            1L,
            new ArrayList<>(List.of(new Equate("b_1_shadow"), new Equate("b_1_1")))
        );

        test.applyDalvikClass("Lobfuscated/Original;", "Lrecovered/pkg/Renamed;");
        Namespace recovered = test.currentProgram.symbols.getNamespace(
            "recovered",
            test.currentProgram.global
        );
        Namespace recoveredPackage = test.currentProgram.symbols.getNamespace("pkg", recovered);
        Namespace renamed = test.currentProgram.symbols.getNamespace("Renamed", recoveredPackage);
        require(renamed != null, "class did not move to the full recovered package path");
        require(
            test.currentProgram.symbols.getNamespace("Original", obfuscated) == null,
            "original class namespace still exists"
        );

        test.applyDalvikMethod(
            "Lquoted/Owner;",
            "a",
            "(Ljava/lang/String;I)I",
            "recoveredMethod"
        );
        require(
            test.functions.get(0x2222L).name.equals("recoveredMethod"),
            "method database symbol was not renamed"
        );

        test.applyDalvikField(
            "Lquoted/Owner;",
            "b",
            "Ljava/lang/String;",
            "recoveredField"
        );
        require(
            test.currentProgram.equates.byValue.get(1L).get(1).name.equals("recoveredField"),
            "field equate was not renamed"
        );
        require(
            test.currentProgram.equates.byValue.get(1L).get(0).name.equals("b_1_shadow"),
            "unrelated same-scalar equate was renamed"
        );
        Symbol fieldLabel = test.currentProgram.symbols.labels.get(0x1078L);
        require(
            fieldLabel != null && fieldLabel.name.equals("recoveredField"),
            "field record label did not use loaded DEX base plus field_ids offset"
        );
    }
}

final class SourceType {
    static final SourceType IMPORTED = new SourceType();
}

final class Address {
    final long value;

    Address(long value) {
        this.value = value;
    }

    Address add(long offset) {
        return new Address(value + offset);
    }
}

final class Namespace {
    String name;
    Namespace parent;
    final Map<String, Namespace> children = new HashMap<>();
    final Symbol symbol;

    Namespace(String name, Namespace parent) {
        this.name = name;
        this.parent = parent;
        this.symbol = parent == null ? null : new Symbol(name, this);
    }

    Symbol getSymbol() {
        return symbol;
    }
}

final class Symbol {
    String name;
    final Namespace namespace;

    Symbol(String name, Namespace namespace) {
        this.name = name;
        this.namespace = namespace;
    }

    void setName(String replacement, SourceType source) {
        name = replacement;
    }

    void setNameAndNamespace(String replacement, Namespace parent, SourceType source) {
        Namespace moved = namespace;
        moved.parent.children.remove(moved.name);
        moved.name = replacement;
        moved.parent = parent;
        name = replacement;
        parent.children.put(replacement, moved);
    }
}

final class SymbolTable {
    final Namespace global;
    final Map<Long, Symbol> labels = new HashMap<>();

    SymbolTable(Namespace global) {
        this.global = global;
    }

    Namespace getNamespace(String name, Namespace parent) {
        return parent == null ? null : parent.children.get(name);
    }

    Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source) {
        return parent.children.computeIfAbsent(name, key -> new Namespace(key, parent));
    }

    Symbol getPrimarySymbol(Address address) {
        return labels.get(address.value);
    }
}

final class Equate {
    String name;

    Equate(String name) {
        this.name = name;
    }

    String getName() {
        return name;
    }

    void renameEquate(String replacement) {
        name = replacement;
    }
}

final class EquateTable {
    final Map<Long, List<Equate>> byValue = new HashMap<>();

    List<Equate> getEquates(long value) {
        return byValue.getOrDefault(value, List.of());
    }
}

final class Function {
    String name;

    Function(String name) {
        this.name = name;
    }

    void setName(String replacement, SourceType source) {
        name = replacement;
    }
}

final class FakeProgram {
    final Namespace global = new Namespace("", null);
    final SymbolTable symbols = new SymbolTable(global);
    final EquateTable equates = new EquateTable();
    final Address minAddress;

    FakeProgram(long minAddress) {
        this.minAddress = new Address(minAddress);
    }

    Namespace getGlobalNamespace() {
        return global;
    }

    SymbolTable getSymbolTable() {
        return symbols;
    }

    EquateTable getEquateTable() {
        return equates;
    }

    Address getMinAddress() {
        return minAddress;
    }
}

final class TypeItem {
    final int type;

    TypeItem(int type) {
        this.type = type;
    }

    int getType() {
        return type;
    }
}

final class TypeList {
    final List<TypeItem> items;

    TypeList(List<TypeItem> items) {
        this.items = items;
    }

    List<TypeItem> getItems() {
        return items;
    }
}

final class PrototypesIDItem {
    final TypeList parameters;
    final int returnType;

    PrototypesIDItem(List<TypeItem> parameters, int returnType) {
        this.parameters = new TypeList(parameters);
        this.returnType = returnType;
    }

    TypeList getParameters() {
        return parameters;
    }

    int getReturnTypeIndex() {
        return returnType;
    }
}

final class MethodIDItem {
    final short classIndex;
    final short prototypeIndex;
    final int nameIndex;

    MethodIDItem(int classIndex, int prototypeIndex, int nameIndex) {
        this.classIndex = (short) classIndex;
        this.prototypeIndex = (short) prototypeIndex;
        this.nameIndex = nameIndex;
    }

    short getClassIndex() {
        return classIndex;
    }

    short getProtoIndex() {
        return prototypeIndex;
    }

    int getNameIndex() {
        return nameIndex;
    }
}

final class FieldIDItem {
    final short classIndex;
    final short typeIndex;
    final int nameIndex;

    FieldIDItem(int classIndex, int typeIndex, int nameIndex) {
        this.classIndex = (short) classIndex;
        this.typeIndex = (short) typeIndex;
        this.nameIndex = nameIndex;
    }

    short getClassIndex() {
        return classIndex;
    }

    short getTypeIndex() {
        return typeIndex;
    }

    int getNameIndex() {
        return nameIndex;
    }
}

final class FakeHeader {
    final List<String> types = new ArrayList<>();
    final List<String> strings = new ArrayList<>();
    final List<PrototypesIDItem> prototypes = new ArrayList<>();
    final List<MethodIDItem> methods = new ArrayList<>();
    final List<FieldIDItem> fields = new ArrayList<>();

    int getTypeIdsSize() {
        return types.size();
    }

    int getMethodIdsSize() {
        return methods.size();
    }

    int getFieldIdsSize() {
        return fields.size();
    }

    int getFieldIdsOffset() {
        return 0x70;
    }

    List<PrototypesIDItem> getPrototypes() {
        return prototypes;
    }

    List<MethodIDItem> getMethods() {
        return methods;
    }

    List<FieldIDItem> getFields() {
        return fields;
    }

    Address getMethodAddress(FakeProgram program, int methodIndex) {
        return new Address(0x2222L + methodIndex);
    }
}

final class DexUtil {
    static String convertTypeIndexToString(FakeHeader header, int typeIndex) {
        return header.types.get(typeIndex);
    }

    static String convertToString(FakeHeader header, int nameIndex) {
        return header.strings.get(nameIndex);
    }
}
"#,
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dalvik-ghidra-semantics");
    let harness_path: PathBuf = scratch.path().join("DalvikMutationHarness.java");
    std::fs::write(&harness_path, harness.as_bytes()).expect("write Ghidra semantic harness");
    let compile: Output = Command::new("javac")
        .arg("-encoding")
        .arg("UTF-8")
        .arg(&harness_path)
        .output()
        .expect("compile Ghidra semantic harness");
    assert!(
        compile.status.success(),
        "Ghidra semantic harness did not compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let execute: Output = Command::new("java")
        .arg("-cp")
        .arg(scratch.path())
        .arg("DalvikMutationHarness")
        .output()
        .expect("execute Ghidra semantic harness");
    assert!(
        execute.status.success(),
        "Ghidra semantic harness rejected database mutations: {}",
        String::from_utf8_lossy(&execute.stderr)
    );
}

fn dalvik_method(original_name: String, descriptor: String, replacement: String) -> ExportSymbol {
    ExportSymbol {
        key: SymbolKey::Dalvik(DalvikSymbolKey::Method {
            owner: "Lquoted/Owner;".to_owned(),
            original_name,
            descriptor,
        }),
        name: replacement,
        demangled: None,
        class: SymbolClass::Method,
        origin: SymbolOrigin::DalvikIdentifier,
        note: None,
    }
}

fn symbol_export(symbols: Vec<ExportSymbol>) -> SymbolExport {
    SymbolExport {
        schema: SYMBOL_EXPORT_SCHEMA,
        source: "tracked.dex".to_owned(),
        format: "dex-dalvik".to_owned(),
        image_base: None,
        original_entry_point: None,
        symbol_count: symbols.len(),
        symbols,
        provenance: Vec::new(),
    }
}

#[test]
fn jvm_decompile_exports_descriptor_keyed_dalvik_symbols() {
    let (scratch, run, map_path): (disrobe_core::scratch::ScratchDir, Run, PathBuf) =
        run_jvm_export("json");

    assert_eq!(run.code, 0, "Dalvik symbol export failed: {}", run.stderr);
    let map_text: String = std::fs::read_to_string(&map_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", map_path.display()));
    let map: serde_json::Value = serde_json::from_str(&map_text).expect("parse symbol map JSON");
    assert_eq!(map["schema"], "disrobe.symbol-map/v2");
    assert_eq!(map["format"], "dex-dalvik");
    let symbols: &Vec<serde_json::Value> = map["symbols"]
        .as_array()
        .expect("symbol map must contain an array");
    assert!(symbols.iter().all(|symbol: &serde_json::Value| {
        symbol.get("address").is_none() && symbol["key"].as_str().is_some()
    }));
    assert!(symbols.iter().any(|symbol: &serde_json::Value| {
        symbol["key"] == "dalvik-class"
            && symbol["descriptor"] == "LEdgeCases;"
            && symbol["name"] == "LEdgeCases;"
    }));
    assert!(symbols.iter().any(|symbol: &serde_json::Value| {
        symbol["key"] == "dalvik-method"
            && symbol["owner"] == "LEdgeCases;"
            && symbol["original_name"] == "gcd"
            && symbol["name"] == "gcd"
            && symbol["descriptor"] == "(II)I"
    }));
    assert!(symbols.iter().any(|symbol: &serde_json::Value| {
        symbol["key"] == "dalvik-field"
            && symbol["owner"] == "LEdgeCases;"
            && symbol["original_name"] == "MAGIC"
            && symbol["name"] == "MAGIC"
            && symbol["descriptor"] == "I"
    }));
    drop(scratch);
}

#[test]
fn dalvik_scripts_are_parseable_chunked_and_deterministic() {
    for format in ["ghidra", "ida", "json"] {
        let (scratch, run, sidecar): (disrobe_core::scratch::ScratchDir, Run, PathBuf) =
            run_jvm_export(format);
        assert_eq!(run.code, 0, "Dalvik {format} export failed: {}", run.stderr);
        let bytes: Vec<u8> = std::fs::read(&sidecar)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", sidecar.display()));
        let (repeat_scratch, repeat_run, repeat_sidecar): (
            disrobe_core::scratch::ScratchDir,
            Run,
            PathBuf,
        ) = run_jvm_export(format);
        assert_eq!(
            repeat_run.code, 0,
            "repeated Dalvik {format} export failed: {}",
            repeat_run.stderr
        );
        let repeat_bytes: Vec<u8> =
            std::fs::read(&repeat_sidecar).unwrap_or_else(|error: std::io::Error| {
                panic!("read {}: {error}", repeat_sidecar.display())
            });
        assert_eq!(bytes, repeat_bytes, "{format} export changed between runs");
        let text: String = String::from_utf8(bytes).expect("export must be UTF-8");
        match format {
            "ghidra" => {
                assert!(text.contains("applyChunk0()"));
                assert!(text.contains("applyChunk1()"));
                parse_java(&text);
            }
            "ida" => compile_python(&text),
            "json" => {
                let _: serde_json::Value =
                    serde_json::from_str(&text).expect("parse repeated symbol map JSON");
            }
            _ => panic!("unexpected format {format}"),
        }
        drop((scratch, repeat_scratch));
    }
}

#[test]
fn shared_formatter_handles_empty_escaped_duplicate_and_chunk_boundary_entries() {
    let empty: SymbolExport = symbol_export(Vec::new());
    let empty_json: String = render_symbol_map_json(&empty).expect("render empty JSON");
    let empty_map: serde_json::Value =
        serde_json::from_str(&empty_json).expect("parse empty JSON map");
    assert_eq!(empty_map["symbol_count"], 0);
    assert_eq!(empty_map["symbols"], serde_json::json!([]));
    parse_java(&render_ghidra_postscript(&empty).expect("render empty Ghidra script"));
    compile_python(&render_idapython(&empty).expect("render empty IDAPython script"));

    let escaped_name: String = "valid\u{1F680}".to_owned();
    let escaped: ExportSymbol = dalvik_method(
        "quoted\"slash\\line\n\ttag\u{1F680}".to_owned(),
        "(Ljava/lang/String;)V".to_owned(),
        escaped_name.clone(),
    );
    let escaped_export: SymbolExport = symbol_export(vec![escaped.clone(), escaped]);
    let escaped_json: String =
        render_symbol_map_json(&escaped_export).expect("render escaped JSON");
    let escaped_map: serde_json::Value =
        serde_json::from_str(&escaped_json).expect("parse escaped JSON map");
    assert_eq!(escaped_map["symbol_count"], 1);
    assert_eq!(escaped_map["symbols"][0]["name"], escaped_name);
    parse_java(&render_ghidra_postscript(&escaped_export).expect("render escaped Ghidra script"));
    compile_python(&render_idapython(&escaped_export).expect("render escaped IDAPython script"));

    let case_distinct: SymbolExport = symbol_export(vec![
        dalvik_method("Name".to_owned(), "()V".to_owned(), "Recovered".to_owned()),
        dalvik_method("name".to_owned(), "()V".to_owned(), "recovered".to_owned()),
    ]);
    let case_json: serde_json::Value = serde_json::from_str(
        &render_symbol_map_json(&case_distinct).expect("render case-distinct JSON"),
    )
    .expect("parse case-distinct JSON");
    assert_eq!(case_json["symbol_count"], 2);

    let symbols: Vec<ExportSymbol> = (0..257_usize)
        .map(|index: usize| {
            let name: String = format!("method{index:03}");
            dalvik_method(name.clone(), "()V".to_owned(), name)
        })
        .collect();
    let chunked: String =
        render_ghidra_postscript(&symbol_export(symbols)).expect("render chunked Ghidra script");
    assert!(chunked.contains("applyChunk0()"));
    assert!(chunked.contains("applyChunk1()"));
    assert!(!chunked.contains("applyChunk2()"));
    parse_java(&chunked);
}

#[test]
fn shared_formatter_rejects_invalid_and_conflicting_dalvik_replacements() {
    let invalid: SymbolExport = symbol_export(vec![dalvik_method(
        "a".to_owned(),
        "()V".to_owned(),
        "not/a/member".to_owned(),
    )]);
    let invalid_error: disrobe_pass_native::Error =
        render_symbol_map_json(&invalid).expect_err("invalid Dalvik replacement must fail");
    assert!(invalid_error.to_string().contains("not/a/member"));

    let conflicting: SymbolExport = symbol_export(vec![
        dalvik_method("a".to_owned(), "()V".to_owned(), "first".to_owned()),
        dalvik_method("a".to_owned(), "()V".to_owned(), "second".to_owned()),
    ]);
    let conflict_error: disrobe_pass_native::Error = render_symbol_map_json(&conflicting)
        .expect_err("one Dalvik key cannot carry conflicting replacements");
    assert!(conflict_error.to_string().contains("conflicting"));
}

#[test]
fn dalvik_scripts_resolve_original_database_identity_before_renaming() {
    let class: ExportSymbol = ExportSymbol {
        key: SymbolKey::Dalvik(DalvikSymbolKey::Class {
            descriptor: "Lobfuscated/Original;".to_owned(),
        }),
        name: "Lrecovered/pkg/Renamed;".to_owned(),
        demangled: None,
        class: SymbolClass::Class,
        origin: SymbolOrigin::DalvikIdentifier,
        note: None,
    };
    let method: ExportSymbol = dalvik_method(
        "a".to_owned(),
        "(Ljava/lang/String;I)I".to_owned(),
        "recoveredMethod".to_owned(),
    );
    let field: ExportSymbol = ExportSymbol {
        key: SymbolKey::Dalvik(DalvikSymbolKey::Field {
            owner: "Lquoted/Owner;".to_owned(),
            original_name: "b".to_owned(),
            descriptor: "Ljava/lang/String;".to_owned(),
        }),
        name: "recoveredField".to_owned(),
        demangled: None,
        class: SymbolClass::Field,
        origin: SymbolOrigin::DalvikIdentifier,
        note: None,
    };
    let export: SymbolExport = symbol_export(vec![class, method, field]);

    let ghidra: String = render_ghidra_postscript(&export).expect("render Ghidra script");
    assert!(ghidra.contains("DexAnalysisState.getState(currentProgram)"));
    assert!(ghidra.contains("header.getMethodAddress(currentProgram, methodIndex)"));
    assert!(ghidra.contains("renameEquate(replacement)"));
    assert!(ghidra.contains("setName(replacement, SourceType.IMPORTED)"));
    assert!(ghidra.contains("replacement.equals(originalName)"));
    assert!(!ghidra.contains("Disrobe Dalvik Symbols"));
    parse_java(&ghidra);
    execute_ghidra_dalvik_mutations(&ghidra);

    let ida: String = render_idapython(&export).expect("render IDAPython script");
    assert!(ida.contains("from idadex import Dex"));
    assert!(ida.contains("Dex.DEXVAR_METH_STRO"));
    assert!(ida.contains("ida_name.set_name"));
    assert!(ida.contains("Dex.DEXVAR_TYPE_RENS"));
    assert!(ida.contains("replacement == original_name"));
    assert!(!ida.contains("$ disrobe.dalvik.symbols"));
    compile_python(&ida);
    execute_ida_dalvik_mutations(&ida);
}
