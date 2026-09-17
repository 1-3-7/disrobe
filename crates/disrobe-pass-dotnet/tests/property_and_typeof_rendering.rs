#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

fn statement_lines(body: &str) -> String {
    body.lines()
        .filter(|line: &&str| {
            let trimmed: &str = line.trim_start();
            let is_comment: bool = trimmed.starts_with("//");
            let is_accessor_decl: bool = (trimmed.contains("get_") || trimmed.contains("set_"))
                && trimmed.ends_with(')')
                && (trimmed.starts_with("private")
                    || trimmed.starts_with("public")
                    || trimmed.starts_with("protected")
                    || trimmed.starts_with("internal")
                    || trimmed.starts_with("static"));
            !is_comment && !is_accessor_decl
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn property_getter_calls_lower_to_member_access() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        let stmts: String = statement_lines(&m.body);
        assert!(
            !stmts.contains("get_"),
            "a property-getter call must render as `obj.Prop`, not a raw get_X call in {}; got:\n{}",
            m.signature,
            m.body
        );
    }
    let sum_async: &str = &asm
        .methods
        .iter()
        .find(|m| m.signature.contains("SumAsync") && m.signature.contains("Task<int>"))
        .expect("SumAsync stub")
        .body;
    assert!(
        sum_async.contains(".Task"),
        "the async builder's get_Task() must render as `.Task`; got:\n{sum_async}"
    );
    assert!(
        !sum_async.contains("get_Task"),
        "no raw get_Task call may survive; got:\n{sum_async}"
    );
}

#[test]
fn property_setter_calls_lower_to_assignment() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        let stmts: String = statement_lines(&m.body);
        assert!(
            !stmts.contains("set_"),
            "a property-setter call must render as `obj.Prop = value`, not a raw set_X call in {}; got:\n{}",
            m.signature,
            m.body
        );
    }
}

#[test]
fn typeof_collapses_gettypefromhandle() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        assert!(
            !m.body.contains("GetTypeFromHandle"),
            "Type.GetTypeFromHandle(typeof(T)) must collapse to typeof(T) in {}; got:\n{}",
            m.signature,
            m.body
        );
    }
    let contract: &str = &asm
        .methods
        .iter()
        .find(|m| m.signature.contains("get_EqualityContract"))
        .expect("record EqualityContract accessor")
        .body;
    assert!(
        contract.contains("typeof(Point)"),
        "the record EqualityContract getter must render `typeof(Point)`; got:\n{contract}"
    );
}

fn decompile_edge_cases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

#[test]
fn indexer_accessor_calls_lower_to_subscripts() {
    let asm: DecompiledAssembly = decompile_edge_cases();
    let mut subscripted: usize = 0;
    for m in &asm.methods {
        let stmts: String = statement_lines(&m.body);
        for accessor in ["get_Item(", "set_Item(", "get_Chars(", "set_Chars("] {
            assert!(
                !stmts.contains(accessor),
                "an indexer access must render as `receiver[index]`, not a raw {accessor} call in {}; got:\n{}",
                m.signature,
                m.body
            );
        }
        subscripted += usize::from(stmts.contains(']'));
    }
    assert!(
        subscripted > 0,
        "no recovered body carries a subscript, so this check would pass even if every indexer access had disappeared"
    );
}

#[test]
fn generic_methods_declare_their_type_parameters() {
    let asm: DecompiledAssembly = decompile_edge_cases();
    let throw_if_null: &str = &asm
        .methods
        .iter()
        .find(|m| m.signature.contains("ThrowIfNull"))
        .expect("EdgeCases.ExceptionPlayground.ThrowIfNull")
        .signature;
    assert!(
        throw_if_null.contains("ThrowIfNull<T>("),
        "a generic method must declare its type parameters, otherwise the recovered signature names a type that is not in scope; got:\n{throw_if_null}"
    );
}

#[test]
fn decompile_remains_lossless_after_property_typeof_lowering() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after the lowering; got {} failures",
        asm.methods_failed
    );
}
