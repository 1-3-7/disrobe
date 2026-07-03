#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const NAMESPACE: &str = "Sample";

#[derive(Debug, Clone, Copy)]
struct Target {
    dll: &'static str,
    type_name: &'static str,
    is_static: bool,
}

const TARGETS: &[Target] = &[
    Target {
        dll: "../../corpus/dotnet/constructs/Constructs.dll",
        type_name: "Constructs",
        is_static: true,
    },
    Target {
        dll: "../../corpus/dotnet/shapes/Shapes.dll",
        type_name: "Shapes",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/guards/Guards.dll",
        type_name: "Guards",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/ranges/Ranges.dll",
        type_name: "Ranges",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/patterns/Patterns.dll",
        type_name: "Patterns",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/typepat/TypeMatch.dll",
        type_name: "TypeMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/proppat/PropMatch.dll",
        type_name: "PropMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/typerel/TypeRel.dll",
        type_name: "TypeRel",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/listpat/ListMatch.dll",
        type_name: "ListMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/branches/Branches.dll",
        type_name: "Branches",
        is_static: false,
    },
];

fn manifest(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    path
}

fn dotnet_available() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn ilspy_available() -> bool {
    Command::new("ilspycmd")
        .env("DOTNET_ROLL_FORWARD", "LatestMajor")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn declaring_type_of(body: &str) -> Option<String> {
    let first: &str = body.lines().next()?;
    let rest: &str = first.trim_start().strip_prefix("//")?.trim();
    let name: &str = rest.split_whitespace().next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn is_compiler_generated_type(full_name: &str) -> bool {
    let short: &str = full_name.rsplit('.').next().unwrap_or(full_name);
    short.contains('<') || short.contains(">d__") || short.starts_with("<>")
}

fn signature_line(body: &str) -> Option<(usize, String)> {
    body.lines().enumerate().find_map(|(i, l): (usize, &str)| {
        let t: &str = l.trim_start();
        let is_decl: bool = !t.starts_with("//")
            && t.contains('(')
            && (t.starts_with("public")
                || t.starts_with("private")
                || t.starts_with("protected")
                || t.starts_with("internal")
                || t.starts_with("static"));
        is_decl.then(|| (i, l.to_owned()))
    })
}

fn method_name_of(decl: &str) -> Option<String> {
    let before_paren: &str = decl.split('(').next()?;
    let ident: &str = before_paren.split_whitespace().next_back()?;
    (!ident.is_empty()
        && ident
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| ident.to_owned())
}

fn promote_visibility_to_public(decl: &str) -> String {
    let trimmed: &str = decl.trim_start();
    let mut rest: &str = trimmed;
    for kw in [
        "public ",
        "private protected ",
        "protected internal ",
        "private ",
        "protected ",
        "internal ",
    ] {
        if let Some(r) = rest.strip_prefix(kw) {
            rest = r;
            break;
        }
    }
    format!("public {rest}")
}

#[derive(Debug, Clone)]
struct UserMethod {
    name: String,
    source: String,
}

fn user_method_for(body: &str, target_type: &str) -> Option<UserMethod> {
    let declaring_type: String = declaring_type_of(body)?;
    if is_compiler_generated_type(&declaring_type) {
        return None;
    }
    let short: &str = declaring_type.rsplit('.').next().unwrap_or(&declaring_type);
    if short != target_type {
        return None;
    }
    let first_line: &str = body.lines().next().unwrap_or_default();
    if first_line.contains("compiler-generated") || first_line.contains("[record") {
        return None;
    }
    let (decl_line, decl): (usize, String) = signature_line(body)?;
    let name: String = method_name_of(&decl)?;
    let promoted: String = promote_visibility_to_public(&decl);
    let tail: String = body
        .lines()
        .skip(decl_line + 1)
        .collect::<Vec<&str>>()
        .join("\n");
    let source: String = format!("    {promoted}\n{tail}\n");
    Some(UserMethod { name, source })
}

const PREAMBLE: &str = "using System;\nusing System.Text;\nusing System.Collections.Generic;\nusing System.Linq;\nusing System.Threading.Tasks;\nusing System.Runtime.CompilerServices;\n\n";

fn whole_type_source(methods: &[UserMethod], target: Target) -> String {
    let bodies: String = methods
        .iter()
        .map(|m: &UserMethod| m.source.clone())
        .collect::<Vec<String>>()
        .join("\n");
    let kind: &str = if target.is_static {
        "public static class"
    } else {
        "public class"
    };
    let type_name: &str = target.type_name;
    format!(
        "{PREAMBLE}namespace {NAMESPACE}\n{{\n    {kind} {type_name}\n    {{\n{bodies}\n    }}\n}}\n"
    )
}

fn write_project(dir: &Path, type_name: &str) {
    let csproj: String = format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <AssemblyName>{type_name}</AssemblyName>\n    <Deterministic>true</Deterministic>\n    <Optimize>true</Optimize>\n    <DebugType>none</DebugType>\n    <NoWarn>CS0168;CS0219;CS0162;CS0164;CS0649;CS1998;CS4014;CS0660;CS0661</NoWarn>\n  </PropertyGroup>\n</Project>\n"
    );
    std::fs::write(dir.join("oracle.csproj"), csproj).expect("write csproj");
}

fn compile_whole_type(dir: &Path, src: &str, type_name: &str) -> (Vec<String>, Option<PathBuf>) {
    std::fs::write(dir.join("host.cs"), src).expect("write source");
    let out: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("dotnet build");
    let errors: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&out.stderr).lines())
        .filter(|l: &&str| l.contains(": error "))
        .map(|l: &str| l.trim().to_owned())
        .collect();
    let dll: PathBuf = dir.join(format!("bin/Release/net9.0/{type_name}.dll"));
    let produced: Option<PathBuf> = dll.exists().then_some(dll);
    (errors, produced)
}

fn ilspy_il(dll: &Path, type_name: &str) -> String {
    let out: std::process::Output = Command::new("ilspycmd")
        .env("DOTNET_ROLL_FORWARD", "LatestMajor")
        .args(["-il", "-t"])
        .arg(format!("{NAMESPACE}.{type_name}"))
        .arg(dll)
        .output()
        .expect("ilspycmd");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn normalize_op(line: &str) -> String {
    let mut out: String = String::new();
    let mut rest: &str = line;
    while let Some(pos) = rest.find("IL_") {
        out.push_str(&rest[..pos]);
        let after: &str = &rest[pos..];
        let hex_len: usize = after["IL_".len()..]
            .bytes()
            .take_while(|b: &u8| b.is_ascii_hexdigit())
            .count();
        out.push('L');
        rest = &after["IL_".len() + hex_len..];
    }
    out.push_str(rest);
    let mut normalized: String = out;
    for pat in ["'<>9__", "'<>9'", ">b__", "'<>c'", "'<>c__"] {
        if normalized.contains(pat) {
            normalized = mask_generated_idents(&normalized);
            break;
        }
    }
    normalized
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn mask_generated_idents(line: &str) -> String {
    let mut out: String = String::new();
    let mut rest: &str = line;
    while let Some(open) = rest.find('\'') {
        out.push_str(&rest[..open]);
        let after: &str = &rest[open + 1..];
        let Some(close): Option<usize> = after.find('\'') else {
            out.push('\'');
            rest = after;
            continue;
        };
        let token: &str = &after[..close];
        if token.contains("<>") || token.contains(">b__") {
            out.push_str("GEN");
        } else {
            out.push('\'');
            out.push_str(token);
            out.push('\'');
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn method_il_ops(il: &str, method: &str, type_name: &str) -> Option<Vec<String>> {
    let mut in_method: bool = false;
    let mut ops: Vec<String> = Vec::new();
    let needle_open: String = format!(" {method} (");
    let needle_open_tight: String = format!(" {method}(");
    let needle_close: String = format!("end of method {type_name}::{method}");
    for line in il.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with(".method") {
            in_method = false;
        }
        if !in_method
            && (line.contains(&needle_open) || line.contains(&needle_open_tight))
            && line.contains(method)
            && looks_like_method_header(line, method)
        {
            in_method = true;
            ops.clear();
        }
        if in_method && let Some(rest) = il_instruction(trimmed) {
            ops.push(normalize_op(rest));
        }
        if in_method && line.contains(&needle_close) {
            return Some(ops);
        }
    }
    None
}

fn looks_like_method_header(line: &str, method: &str) -> bool {
    let Some((_, after)): Option<(&str, &str)> = line.split_once(method) else {
        return false;
    };
    after.trim_start().starts_with('(')
}

fn il_instruction(trimmed: &str) -> Option<&str> {
    if !trimmed.starts_with("IL_") {
        return None;
    }
    let after_label: &str = trimmed.split_once(':').map(|(_, r): (&str, &str)| r)?;
    let op: &str = after_label.trim_start();
    (!op.is_empty()).then_some(op)
}

struct Outcome {
    compiled: bool,
    compile_errors: Vec<String>,
    equivalent: Vec<String>,
    mismatched: Vec<String>,
    missing: Vec<String>,
}

fn qualify(target: Target, method: &str) -> String {
    format!("{}.{method}", target.type_name)
}

fn run_target(target: Target) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let methods: Vec<UserMethod> = asm
        .methods
        .iter()
        .filter_map(|m: &StructuredMethod| user_method_for(&m.body, target.type_name))
        .collect();
    assert!(
        !methods.is_empty(),
        "expected recovered user methods for {}",
        target.type_name
    );

    let tmp: PathBuf =
        std::env::temp_dir().join(format!("disrobe_whole_type_il_oracle_{}", target.type_name));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    write_project(&tmp, target.type_name);
    let src: String = whole_type_source(&methods, target);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, target.type_name);
        let recomp_il: String = ilspy_il(recompiled, target.type_name);
        let orig_ops: BTreeMap<String, Vec<String>> = methods
            .iter()
            .filter_map(|m: &UserMethod| {
                method_il_ops(&orig_il, &m.name, target.type_name)
                    .map(|ops: Vec<String>| (m.name.clone(), ops))
            })
            .collect();
        for m in &methods {
            let recomp: Option<Vec<String>> = method_il_ops(&recomp_il, &m.name, target.type_name);
            match (orig_ops.get(&m.name), recomp) {
                (Some(o), Some(r)) if *o == r => equivalent.push(qualify(target, &m.name)),
                (Some(_), Some(_)) => mismatched.push(qualify(target, &m.name)),
                _ => missing.push(qualify(target, &m.name)),
            }
        }
    }
    Outcome {
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordTarget {
    dll: &'static str,
    type_name: &'static str,
}

const RECORD_TARGETS: &[RecordTarget] = &[RecordTarget {
    dll: "../../corpus/dotnet/constructs/Constructs.dll",
    type_name: "Point",
}];

#[derive(Debug, Clone)]
struct RecordComponent {
    ty: String,
    name: String,
}

fn signature_only(body: &str) -> Option<&str> {
    body.lines()
        .find(|l: &&str| !l.trim_start().starts_with("//") && l.contains('('))
}

fn record_member_bodies<'a>(asm: &'a DecompiledAssembly, type_name: &str) -> Vec<&'a str> {
    let needle: String = format!(".{type_name} [record");
    asm.methods
        .iter()
        .filter_map(|m: &'a StructuredMethod| {
            let first: &str = m.body.lines().next().unwrap_or_default();
            first.contains(&needle).then_some(m.body.as_str())
        })
        .collect()
}

fn parse_ctor_components(decl: &str) -> Option<Vec<RecordComponent>> {
    let open: usize = decl.find(".ctor(")? + ".ctor(".len();
    let rest: &str = &decl[open..];
    let close: usize = rest.find(')')?;
    let inner: &str = rest[..close].trim();
    if inner.is_empty() {
        return None;
    }
    let mut out: Vec<RecordComponent> = Vec::new();
    for part in inner.split(',') {
        let part: &str = part.trim();
        let (ty, name): (&str, &str) = part.rsplit_once(' ')?;
        let ty: String = ty.trim().rsplit('.').next().unwrap_or(ty).to_owned();
        let name: &str = name.trim();
        if ty.is_empty() || name.is_empty() {
            return None;
        }
        out.push(RecordComponent {
            ty,
            name: name.to_owned(),
        });
    }
    Some(out)
}

fn reconstruct_record_decl(asm: &DecompiledAssembly, type_name: &str) -> Option<String> {
    let members: Vec<&str> = record_member_bodies(asm, type_name);
    if members.is_empty() {
        return None;
    }
    let qualified: String = format!(".{type_name}");
    let primary: Vec<RecordComponent> = members
        .iter()
        .filter_map(|body: &&str| signature_only(body))
        .filter(|decl: &&str| {
            decl.contains(".ctor(") && !decl.contains(&format!("{qualified} original)"))
        })
        .find_map(parse_ctor_components)?;
    let params: String = primary
        .iter()
        .map(|c: &RecordComponent| format!("{} {}", c.ty, c.name))
        .collect::<Vec<String>>()
        .join(", ");
    Some(format!("public record {type_name}({params});"))
}

fn record_source(decl: &str) -> String {
    format!("{PREAMBLE}namespace {NAMESPACE}\n{{\n    {decl}\n}}\n")
}

fn il_method_blocks(il: &str, type_name: &str) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut blocks: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    let close_prefix: String = format!("end of method {type_name}::");
    let mut in_method: bool = false;
    let mut ops: Vec<String> = Vec::new();
    for line in il.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with(".method") {
            in_method = true;
            ops.clear();
        }
        if in_method && let Some(rest) = il_instruction(trimmed) {
            ops.push(normalize_op(rest));
        }
        if in_method && let Some(pos) = line.find(&close_prefix) {
            let name: &str = line[pos + close_prefix.len()..].trim();
            blocks.entry(name.to_owned()).or_default().push(ops.clone());
            in_method = false;
            ops.clear();
        }
    }
    blocks
}

fn run_record_target(target: RecordTarget) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let Some(decl): Option<String> = reconstruct_record_decl(&asm, target.type_name) else {
        return Outcome {
            compiled: false,
            compile_errors: vec![format!(
                "could not reconstruct record declaration for {}",
                target.type_name
            )],
            equivalent: Vec::new(),
            mismatched: Vec::new(),
            missing: vec![target.type_name.to_owned()],
        };
    };

    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_whole_type_il_oracle_record_{}",
        target.type_name
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    write_project(&tmp, target.type_name);
    let src: String = record_source(&decl);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, target.type_name);
        let recomp_il: String = ilspy_il(recompiled, target.type_name);
        let orig_blocks: BTreeMap<String, Vec<Vec<String>>> =
            il_method_blocks(&orig_il, target.type_name);
        let recomp_blocks: BTreeMap<String, Vec<Vec<String>>> =
            il_method_blocks(&recomp_il, target.type_name);
        for (name, orig_ops) in &orig_blocks {
            let qualified: String = format!("{}.{name}", target.type_name);
            match recomp_blocks.get(name) {
                Some(recomp_ops) if multiset_eq(orig_ops, recomp_ops) => {
                    equivalent.push(qualified);
                }
                Some(_) => mismatched.push(qualified),
                None => missing.push(qualified),
            }
        }
    }
    Outcome {
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordMethodTarget {
    dll: &'static str,
    record_type: &'static str,
    class_type: &'static str,
}

const RECORD_METHOD_TARGETS: &[RecordMethodTarget] = &[
    RecordMethodTarget {
        dll: "../../corpus/dotnet/records/Records.dll",
        record_type: "Vec",
        class_type: "Records",
    },
    RecordMethodTarget {
        dll: "../../corpus/dotnet/pospat/PosMatch.dll",
        record_type: "Point",
        class_type: "PosMatch",
    },
];

fn record_method_source(record_decl: &str, methods: &[UserMethod], class_type: &str) -> String {
    let bodies: String = methods
        .iter()
        .map(|m: &UserMethod| m.source.clone())
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        "{PREAMBLE}namespace {NAMESPACE}\n{{\n    {record_decl}\n\n    public class {class_type}\n    {{\n{bodies}\n    }}\n}}\n"
    )
}

fn run_record_method_target(target: RecordMethodTarget) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let Some(record_decl): Option<String> = reconstruct_record_decl(&asm, target.record_type)
    else {
        return Outcome {
            compiled: false,
            compile_errors: vec![format!(
                "could not reconstruct record declaration for {}",
                target.record_type
            )],
            equivalent: Vec::new(),
            mismatched: Vec::new(),
            missing: vec![target.class_type.to_owned()],
        };
    };
    let methods: Vec<UserMethod> = asm
        .methods
        .iter()
        .filter_map(|m: &StructuredMethod| user_method_for(&m.body, target.class_type))
        .collect();
    assert!(
        !methods.is_empty(),
        "expected recovered user methods for {}",
        target.class_type
    );

    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_whole_type_il_oracle_recmeth_{}",
        target.class_type
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    write_project(&tmp, target.class_type);
    let src: String = record_method_source(&record_decl, &methods, target.class_type);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.class_type);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, target.class_type);
        let recomp_il: String = ilspy_il(recompiled, target.class_type);
        let orig_ops: BTreeMap<String, Vec<String>> = methods
            .iter()
            .filter_map(|m: &UserMethod| {
                method_il_ops(&orig_il, &m.name, target.class_type)
                    .map(|ops: Vec<String>| (m.name.clone(), ops))
            })
            .collect();
        for m in &methods {
            let qualified: String = format!("{}.{}", target.class_type, m.name);
            let recomp: Option<Vec<String>> = method_il_ops(&recomp_il, &m.name, target.class_type);
            match (orig_ops.get(&m.name), recomp) {
                (Some(o), Some(r)) if *o == r => equivalent.push(qualified),
                (Some(_), Some(_)) => mismatched.push(qualified),
                _ => missing.push(qualified),
            }
        }
    }
    Outcome {
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
    }
}

fn multiset_eq(a: &[Vec<String>], b: &[Vec<String>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut remaining: Vec<&Vec<String>> = b.iter().collect();
    for item in a {
        if let Some(pos) = remaining.iter().position(|c: &&Vec<String>| *c == item) {
            remaining.swap_remove(pos);
        } else {
            return false;
        }
    }
    remaining.is_empty()
}

fn run_oracle() -> Option<Vec<Outcome>> {
    if !dotnet_available() || !ilspy_available() {
        return None;
    }
    let mut outcomes: Vec<Outcome> = TARGETS.iter().map(|t: &Target| run_target(*t)).collect();
    outcomes.extend(
        RECORD_TARGETS
            .iter()
            .map(|t: &RecordTarget| run_record_target(*t)),
    );
    outcomes.extend(
        RECORD_METHOD_TARGETS
            .iter()
            .map(|t: &RecordMethodTarget| run_record_method_target(*t)),
    );
    Some(outcomes)
}

const IL_EQUIVALENCE_FLOOR: usize = 47;

#[test]
fn whole_type_recompiles_to_equivalent_il() {
    let Some(outcomes): Option<Vec<Outcome>> = run_oracle() else {
        eprintln!("SKIP whole-type IL oracle: dotnet SDK or ilspycmd not available");
        return;
    };
    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for outcome in &outcomes {
        assert!(
            outcome.compiled,
            "recovered whole-type source did not recompile. csc errors:\n{}",
            outcome.compile_errors.join("\n")
        );
        equivalent.extend(outcome.equivalent.iter().cloned());
        mismatched.extend(outcome.mismatched.iter().cloned());
        missing.extend(outcome.missing.iter().cloned());
    }
    eprintln!(
        "WHOLE-TYPE IL EQUIVALENCE ({} types in {NAMESPACE}): {} methods IL-equivalent after standalone csc recompile + ilspycmd compare against the original assembly",
        outcomes.len(),
        equivalent.len()
    );
    eprintln!("  equivalent: {equivalent:?}");
    if !mismatched.is_empty() {
        eprintln!("  IL-mismatched (recovered shape differs): {mismatched:?}");
    }
    if !missing.is_empty() {
        eprintln!("  not located in one assembly: {missing:?}");
    }
    assert!(
        equivalent.len() >= IL_EQUIVALENCE_FLOOR,
        "whole-type IL-equivalence regressed below the floor: {}/{} (floor {IL_EQUIVALENCE_FLOOR}). mismatched={mismatched:?} missing={missing:?}",
        equivalent.len(),
        equivalent.len() + mismatched.len() + missing.len(),
    );
}
