#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::iterator_reverse::is_unlowered_compiler_construct_refusal;
use disrobe_pass_dotnet::structurize::StructuredMethod;

fn manifest(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    path
}

fn require_dotnet(grader: &str) {
    let probe: std::io::Result<std::process::Output> =
        Command::new("dotnet").arg("--version").output();
    let reached: bool = matches!(&probe, Ok(output) if output.status.success());
    assert!(
        reached,
        "{grader} grades recovered C# with the real csc that ships in the dotnet SDK, so \
         `dotnet --version` must succeed here. it did not. a grader that cannot reach its \
         compiler reports no measurement at all rather than passing on an empty population"
    );
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = std::fs::read(manifest(
        "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
    ))
    .expect("read EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile")
}

fn move_next_methods(asm: &DecompiledAssembly) -> Vec<&StructuredMethod> {
    asm.methods
        .iter()
        .filter(|m: &&StructuredMethod| {
            m.signature.contains("state machine") && m.signature.contains("MoveNext")
        })
        .collect()
}

fn body_lines(body: &str) -> Vec<&str> {
    body.lines().collect()
}

fn referenced_this_members(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let mut rest: &str = line;
        while let Some(pos) = rest.find("this.") {
            let after: &str = &rest[pos + "this.".len()..];
            let len: usize = after
                .bytes()
                .take_while(|&b: &u8| {
                    b.is_ascii_alphanumeric() || b == b'_' || b == b'<' || b == b'>'
                })
                .count();
            let member: &str = &after[..len];
            if !member.is_empty() {
                out.insert(member.to_owned());
            }
            rest = &after[len.max(1)..];
        }
    }
    out
}

fn sanitize_member(member: &str) -> String {
    member.replace(['<', '>'], "_")
}

fn is_cached_delegate_field(token: &str) -> bool {
    let Some(suffix): Option<&str> = token.strip_prefix("__9__") else {
        return false;
    };
    let Some((index, ordinal)): Option<(&str, &str)> = suffix.split_once('_') else {
        return false;
    };
    !index.is_empty()
        && !ordinal.is_empty()
        && index.bytes().all(|b: u8| b.is_ascii_digit())
        && ordinal.bytes().all(|b: u8| b.is_ascii_digit())
}

fn cached_delegate_fields(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut token: String = String::new();
    let flush = |token: &mut String, out: &mut BTreeSet<String>| {
        if is_cached_delegate_field(token) {
            out.insert(token.clone());
        }
        token.clear();
    };
    for ch in body.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            token.push(ch);
        } else {
            flush(&mut token, &mut out);
        }
    }
    flush(&mut token, &mut out);
    out
}

fn rewrite_this(body: &str) -> String {
    let mut out: String = body.to_owned();
    for member in referenced_this_members(body) {
        let from: String = format!("this.{member}");
        let to: String = format!("this.{}", sanitize_member(&member));
        out = out.replace(&from, &to);
    }
    out
}

fn is_local_decl(line: &str) -> Option<&str> {
    let t: &str = line.trim();
    if t.starts_with("//") {
        return None;
    }
    let inner: &str = t.strip_suffix(';')?;
    if inner.contains('=') || inner.contains('(') {
        return None;
    }
    let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
    let valid_name: bool = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
        && !is_csharp_keyword(name);
    let ty_lead: &str = ty.split_whitespace().next().unwrap_or(ty);
    (valid_name && !ty.is_empty() && !is_csharp_keyword(ty_lead)).then_some(name)
}

fn decl_uses_generated_type(line: &str) -> bool {
    let t: &str = line.trim();
    let ty: &str = t.rsplit_once(' ').map_or(t, |(ty, _name): (&str, &str)| ty);
    t.contains("Awaiter")
        || t.contains("<>")
        || t.contains("!0")
        || t.contains("!!")
        || ty.contains('.')
        || ty.contains('<')
        || !is_primitive_type(ty)
}

fn is_primitive_type(ty: &str) -> bool {
    matches!(
        ty,
        "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "byte"
            | "sbyte"
            | "bool"
            | "char"
            | "float"
            | "double"
            | "decimal"
            | "string"
            | "object"
            | "nint"
            | "nuint"
    )
}

fn is_csharp_keyword(name: &str) -> bool {
    matches!(
        name,
        "break"
            | "continue"
            | "return"
            | "throw"
            | "yield"
            | "await"
            | "if"
            | "else"
            | "while"
            | "for"
            | "foreach"
            | "switch"
            | "case"
            | "default"
            | "try"
            | "catch"
            | "finally"
            | "goto"
            | "this"
            | "base"
            | "new"
    )
}

fn assigned_identifier(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let (lhs, _rhs): (&str, &str) = t.split_once(" = ")?;
    let name: &str = lhs.trim();
    let simple: bool = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
        && !is_csharp_keyword(name);
    simple.then(|| name.to_owned())
}

fn looks_like_type_parameter(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if first != 'T' && first != 'K' && first != 'U' && first != 'V' {
        return false;
    }
    chars.next().is_none_or(|second: char| {
        first == 'T'
            && second.is_ascii_uppercase()
            && token.bytes().all(|b: u8| b.is_ascii_alphanumeric())
    })
}

fn collect_type_parameters(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut token: String = String::new();
    let flush = |token: &mut String, out: &mut BTreeSet<String>| {
        if !token.is_empty() {
            if looks_like_type_parameter(token) {
                out.insert(token.clone());
            }
            token.clear();
        }
    };
    for ch in body.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            token.push(ch);
        } else {
            flush(&mut token, &mut out);
        }
    }
    flush(&mut token, &mut out);
    out
}

fn host_source(id: usize, body: &str) -> Option<String> {
    if is_unlowered_compiler_construct_refusal(body) {
        return None;
    }
    let lines: Vec<&str> = body_lines(body);
    let open: usize = lines.iter().position(|l: &&str| l.trim() == "{")?;
    let close: usize = lines.iter().rposition(|l: &&str| l.trim() == "}")?;
    if close <= open {
        return None;
    }
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut kept: Vec<String> = Vec::new();
    for line in &lines[open + 1..close] {
        if let Some(name) = is_local_decl(line) {
            if decl_uses_generated_type(line) {
                kept.push(format!("        dynamic {name} = default;"));
            } else {
                let ty: &str = line
                    .trim()
                    .rsplit_once(' ')
                    .map_or("", |(t, _): (&str, &str)| t);
                kept.push(format!("        {ty} {name} = default;"));
            }
            declared.insert(name.to_owned());
            continue;
        }
        kept.push((*line).to_owned());
    }
    let extra: BTreeSet<String> = kept
        .iter()
        .filter_map(|l: &String| assigned_identifier(l))
        .filter(|n: &String| !declared.contains(n))
        .collect();
    let extra_decls: String = extra
        .iter()
        .map(|n: &String| format!("        dynamic {n} = default;"))
        .collect::<Vec<String>>()
        .join("\n");
    let inner: String = kept.join("\n");
    let rewritten: String = rewrite_this(&inner);
    let mut members: BTreeSet<String> = referenced_this_members(body)
        .into_iter()
        .map(|m: String| sanitize_member(&m))
        .collect();
    members.extend(cached_delegate_fields(&rewritten));
    let field_decls: String = members
        .iter()
        .map(|m: &String| format!("    public dynamic {m} = null;"))
        .collect::<Vec<String>>()
        .join("\n");
    let has_yield: bool = rewritten.contains("yield return") || rewritten.contains("yield break");
    let has_await: bool = rewritten.contains("await ");
    let returns_value: bool = rewritten
        .lines()
        .any(|l: &str| l.trim().starts_with("return ") && l.trim() != "return;");
    let head: &str = match (has_yield, has_await, returns_value) {
        (true, true, _) => "public async IAsyncEnumerable<dynamic> __run()",
        (true, false, _) => "public IEnumerable<dynamic> __run()",
        (false, true, true) => "public async Task<dynamic> __run()",
        (false, true, false) => "public async Task __run()",
        (false, false, true) => "public dynamic __run()",
        (false, false, false) => "public void __run()",
    };
    let type_params: BTreeSet<String> = collect_type_parameters(&rewritten);
    let generics: String = if type_params.is_empty() {
        String::new()
    } else {
        format!(
            "<{}>",
            type_params
                .iter()
                .cloned()
                .collect::<Vec<String>>()
                .join(", ")
        )
    };
    let tail: &str = match (has_yield, has_await, returns_value) {
        (false, true | false, true) => "\n        return default;",
        _ => "",
    };
    let stubs: String = unknown_type_stubs(&format!("{extra_decls}\n{rewritten}"));
    let (bases, iface_members): (String, String) = value_task_source_impl(&rewritten);
    Some(format!(
        "{stubs}public class __Mover{id}{generics}{bases}\n{{\n{field_decls}\n    public dynamic __builder = null;\n{iface_members}    {head}\n    {{\n{extra_decls}\n{rewritten}{tail}\n    }}\n}}\n"
    ))
}

fn value_task_source_self_arg(body: &str) -> Option<String> {
    for marker in ["new ValueTask", "new System.Threading.Tasks.ValueTask"] {
        let mut rest: &str = body;
        while let Some(pos) = rest.find(marker) {
            let after: &str = &rest[pos + marker.len()..];
            let generic: &str = after
                .strip_prefix('<')
                .map_or("", |tail: &str| tail.split('>').next().unwrap_or(""));
            let post_generic: &str = if after.starts_with('<') {
                after
                    .split_once('>')
                    .map_or("", |(_, t): (&str, &str)| t)
                    .trim_start()
            } else {
                after.trim_start()
            };
            if post_generic.starts_with("(this,") || post_generic.starts_with("(this ,") {
                return Some(generic.trim().to_owned());
            }
            rest = &rest[pos + marker.len()..];
        }
    }
    None
}

fn value_task_source_impl(body: &str) -> (String, String) {
    let Some(generic): Option<String> = value_task_source_self_arg(body) else {
        return (String::new(), String::new());
    };
    let iface: String = if generic.is_empty() {
        "System.Threading.Tasks.Sources.IValueTaskSource".to_owned()
    } else {
        format!("System.Threading.Tasks.Sources.IValueTaskSource<{generic}>")
    };
    let get_result: String = if generic.is_empty() {
        "    public void GetResult(short token) { }\n".to_owned()
    } else {
        format!("    public {generic} GetResult(short token) {{ return default; }}\n")
    };
    let members: String = format!(
        "{get_result}    public System.Threading.Tasks.Sources.ValueTaskSourceStatus GetStatus(short token) {{ return default; }}\n    public void OnCompleted(System.Action<object> continuation, object state, short token, System.Threading.Tasks.Sources.ValueTaskSourceOnCompletedFlags flags) {{ }}\n"
    );
    (format!(" : {iface}"), members)
}

fn unknown_type_stubs(body: &str) -> String {
    let mut bare: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut edgecases_root: BTreeSet<String> = BTreeSet::new();
    let mut edgecases_more: BTreeSet<String> = BTreeSet::new();
    for path in type_position_paths(body) {
        if let Some(rest) = path.strip_prefix("EdgeCases.More.") {
            if let Some(leaf) = simple_leaf(rest) {
                edgecases_more.insert(leaf.to_owned());
            }
        } else if let Some(rest) = path.strip_prefix("EdgeCases.") {
            if let Some(leaf) = simple_leaf(rest) {
                edgecases_root.insert(leaf.to_owned());
            }
        } else if !path.contains('.') && is_stub_type_name(&path) {
            bare.entry(path).or_insert(0);
        }
    }
    for (name, arity) in new_expression_arities(body) {
        if is_stub_type_name(&name) {
            let slot: &mut usize = bare.entry(name).or_insert(0);
            *slot = (*slot).max(arity);
        }
    }
    let ctor_arities: std::collections::BTreeMap<String, usize> = new_expression_ctor_arities(body);
    let mut out: String = String::new();
    for (name, arity) in &bare {
        let ctor: String = ctor_arities
            .get(name)
            .copied()
            .filter(|&n: &usize| n > 0)
            .map_or_else(String::new, |n: usize| ctor_member(name, n));
        let _ = writeln!(
            out,
            "public class {name}{}\n{{\n{ctor}}}",
            type_param_clause(*arity)
        );
    }
    if !edgecases_root.is_empty() || !edgecases_more.is_empty() {
        out.push_str("namespace EdgeCases\n{\n");
        for name in &edgecases_root {
            out.push_str(&namespaced_stub(name, "EdgeCases", &ctor_arities));
        }
        out.push_str("}\n");
    }
    if !edgecases_more.is_empty() {
        out.push_str("namespace EdgeCases.More\n{\n");
        for name in &edgecases_more {
            out.push_str(&namespaced_stub(name, "EdgeCases.More", &ctor_arities));
        }
        out.push_str("}\n");
    }
    out
}

fn namespaced_stub(
    name: &str,
    namespace: &str,
    ctor_arities: &std::collections::BTreeMap<String, usize>,
) -> String {
    let arity: usize = ctor_arities
        .get(&format!("{namespace}.{name}"))
        .copied()
        .unwrap_or(0);
    if arity == 0 {
        return format!("    public class {name} {{ }}\n");
    }
    format!(
        "    public class {name}\n    {{\n    {}    }}\n",
        ctor_member(name, arity)
    )
}

fn type_param_clause(arity: usize) -> String {
    if arity == 0 {
        return String::new();
    }
    let params: String = (0..arity)
        .map(|i: usize| format!("__T{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    format!("<{params}>")
}

fn new_expression_arities(body: &str) -> std::collections::BTreeMap<String, usize> {
    let mut out: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut rest: &str = body;
    while let Some(pos) = rest.find("new ") {
        let after: &str = &rest[pos + "new ".len()..];
        if let Some(name) = leading_type_path(after)
            && !name.contains('.')
        {
            let tail: &str = &after[name.len()..];
            if let Some(arity) = generic_arity(tail) {
                let slot: &mut usize = out.entry(name).or_insert(0);
                *slot = (*slot).max(arity);
            }
        }
        rest = &rest[pos + "new ".len()..];
    }
    out
}

fn ctor_member(name: &str, arity: usize) -> String {
    let params: String = (0..arity)
        .map(|i: usize| format!("dynamic __a{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    format!("    public {name}({params}) {{ }}\n")
}

fn new_expression_ctor_arities(body: &str) -> std::collections::BTreeMap<String, usize> {
    let mut out: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut rest: &str = body;
    while let Some(pos) = rest.find("new ") {
        let after: &str = &rest[pos + "new ".len()..];
        if let Some(name) = leading_type_path(after) {
            let tail: &str = after[name.len()..].trim_start();
            if let Some(arity) = call_arity(tail) {
                let slot: &mut usize = out.entry(name).or_insert(0);
                *slot = (*slot).max(arity);
            }
        }
        rest = &rest[pos + "new ".len()..];
    }
    out
}

fn skip_generic_args(tail: &str) -> &str {
    let Some(after_open): Option<&str> = tail.strip_prefix('<') else {
        return tail;
    };
    let mut depth: usize = 1;
    for (idx, ch) in after_open.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return after_open[idx + ch.len_utf8()..].trim_start();
                }
            }
            _ => {}
        }
    }
    tail
}

fn call_arity(tail: &str) -> Option<usize> {
    let tail: &str = skip_generic_args(tail);
    let inner: &str = tail.strip_prefix('(')?;
    let mut depth: usize = 1;
    let mut commas: usize = 0;
    let mut seen_token: bool = false;
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(if seen_token { commas + 1 } else { 0 });
                }
            }
            ',' if depth == 1 => commas += 1,
            c if !c.is_whitespace() => seen_token = true,
            _ => {}
        }
    }
    None
}

fn generic_arity(tail: &str) -> Option<usize> {
    let inner: &str = tail.strip_prefix('<')?;
    let mut depth: usize = 1;
    let mut commas: usize = 0;
    for ch in inner.chars() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(commas + 1);
                }
            }
            ',' if depth == 1 => commas += 1,
            _ => {}
        }
    }
    None
}

fn simple_leaf(rest: &str) -> Option<&str> {
    let leaf: &str = rest.split(['.', '<', '>', '[', ' ', ')', ',']).next()?;
    (!leaf.is_empty() && is_stub_type_name(leaf)).then_some(leaf)
}

fn type_position_paths(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    collect_after_keyword(body, "new ", &mut out);
    collect_after_keyword(body, "default(", &mut out);
    collect_generic_arguments(body, &mut out);
    out
}

fn collect_after_keyword(body: &str, keyword: &str, out: &mut BTreeSet<String>) {
    let mut rest: &str = body;
    while let Some(pos) = rest.find(keyword) {
        let after: &str = &rest[pos + keyword.len()..];
        if let Some(path) = leading_type_path(after) {
            out.insert(path);
        }
        rest = &rest[pos + keyword.len()..];
    }
}

fn collect_generic_arguments(body: &str, out: &mut BTreeSet<String>) {
    let bytes: &[u8] = body.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if (b == b'<' || b == b',')
            && let Some(after) = body.get(idx + 1..)
        {
            let trimmed: &str = after.trim_start();
            if let Some(path) = leading_type_path(trimmed)
                && !path_is_call(trimmed, &path)
            {
                out.insert(path);
            }
        }
    }
}

fn path_is_call(s: &str, path: &str) -> bool {
    s[path.len()..].trim_start().starts_with('(')
}

fn leading_type_path(s: &str) -> Option<String> {
    let len: usize = s
        .bytes()
        .take_while(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        .count();
    let path: &str = s[..len].trim_end_matches('.');
    (!path.is_empty()
        && path
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_'))
    .then(|| path.to_owned())
}

fn is_stub_type_name(name: &str) -> bool {
    if name.is_empty()
        || is_primitive_type(name)
        || is_csharp_keyword(name)
        || matches!(
            name,
            "typeof"
                | "nameof"
                | "sizeof"
                | "var"
                | "dynamic"
                | "null"
                | "value"
                | "out"
                | "ref"
                | "in"
                | "is"
                | "as"
                | "await"
                | "true"
                | "false"
        )
    {
        return false;
    }
    if name.bytes().next().is_some_and(|b: u8| b.is_ascii_digit()) {
        return false;
    }
    if looks_like_type_parameter(name) {
        return false;
    }
    !is_known_framework_type(name)
}

fn is_known_framework_type(name: &str) -> bool {
    matches!(
        name,
        "List"
            | "Dictionary"
            | "HashSet"
            | "Queue"
            | "Stack"
            | "IEnumerable"
            | "IEnumerator"
            | "IReadOnlyList"
            | "ICollection"
            | "IList"
            | "KeyValuePair"
            | "ValueTuple"
            | "Tuple"
            | "Task"
            | "ValueTask"
            | "Func"
            | "Action"
            | "Exception"
            | "InvalidOperationException"
            | "ArgumentException"
            | "ArgumentNullException"
            | "CancellationToken"
            | "CancellationTokenSource"
            | "SemaphoreSlim"
            | "BlockingCollection"
            | "TimeSpan"
            | "DateTime"
            | "Guid"
            | "Enumerator"
            | "TaskAwaiter"
            | "ConfiguredTaskAwaitable"
            | "ConfiguredValueTaskAwaitable"
            | "ValueTaskAwaiter"
            | "ConfiguredCancelableAsyncEnumerable"
            | "Object"
            | "String"
            | "EnumerationOptions"
            | "StringBuilder"
            | "DirectoryInfo"
            | "FileInfo"
    )
}

const PREAMBLE: &str = "using System;\nusing System.IO;\nusing System.Text;\nusing System.Threading;\nusing System.Collections.Generic;\nusing System.Collections.Concurrent;\nusing System.Linq;\nusing System.Threading.Tasks;\nusing System.Runtime.CompilerServices;\n\n";

fn write_project(dir: &Path) {
    let csproj: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <NoWarn>CS0168;CS0219;CS0162;CS0164;CS0649;CS1998;CS4014</NoWarn>\n  </PropertyGroup>\n  <ItemGroup>\n    <Reference Include=\"Microsoft.CSharp\" />\n  </ItemGroup>\n</Project>\n";
    std::fs::write(dir.join("oracle.csproj"), csproj).expect("write csproj");
}

fn compile_output(dir: &Path, src: &str) -> std::process::Output {
    std::fs::write(dir.join("host.cs"), src).expect("write host source");
    Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("dotnet build")
}

fn compiler_diagnostics(output: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
        .filter(|l: &&str| l.contains(": error "))
        .map(|l: &str| l.trim().to_owned())
        .collect()
}

fn compiler_succeeded(output: &std::process::Output, diagnostics: &[String]) -> bool {
    output.status.success() && diagnostics.is_empty()
}

const COMPILED_FLOOR: usize = 18;
const EXPECTED_UNLOWERED_COMPILER_CONSTRUCT_REFUSALS: [(u32, &str); 11] = [
    (
        0x0600_0205,
        "// <RangeAsync>d__2 [async iterator state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_0208,
        "// <RangeAsync>d__2 [async iterator state machine]\nprivate System.Threading.Tasks.ValueTask<bool> System.Collections.Generic.IAsyncEnumerator<System.Int32>.MoveNextAsync()",
    ),
    (
        0x0600_021d,
        "// <CountWithAsync>d__1 [async state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_0225,
        "// <ParallelForAsync>d__1 [async state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_0227,
        "// <ProducerConsumerAsync>d__0 [async state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_0233,
        "// <Enumerated>d__2 [iterator state machine]\nprivate bool MoveNext()",
    ),
    (
        0x0600_023c,
        "// <WithEarlyExit>d__1 [iterator state machine]\nprivate bool MoveNext()",
    ),
    (
        0x0600_0245,
        "// <EnumerateFiles>d__0 [iterator state machine]\nprivate bool MoveNext()",
    ),
    (
        0x0600_0293,
        "// <BatchAsync>d__2 [async state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_02a9,
        "// <<BatchAsync>b__0>d [async state machine]\nprivate void MoveNext()",
    ),
    (
        0x0600_02ab,
        "// <<Register>b__0>d [async state machine]\nprivate void MoveNext()",
    ),
];

fn unlowered_compiler_construct_refusals(methods: &[&StructuredMethod]) -> Vec<(u32, String)> {
    methods
        .iter()
        .filter(|method: &&&StructuredMethod| is_unlowered_compiler_construct_refusal(&method.body))
        .map(|method: &&StructuredMethod| (method.token, method.signature.clone()))
        .collect()
}

fn expected_unlowered_compiler_construct_refusals() -> Vec<(u32, String)> {
    EXPECTED_UNLOWERED_COMPILER_CONSTRUCT_REFUSALS
        .iter()
        .map(|(token, signature): &(u32, &str)| (*token, (*signature).to_owned()))
        .collect()
}

#[test]
fn named_refusals_match_the_pinned_state_machine_set() {
    let asm: DecompiledAssembly = decompile();
    let methods: Vec<&StructuredMethod> = move_next_methods(&asm);
    let range_async: &StructuredMethod = asm
        .methods
        .iter()
        .find(|method: &&StructuredMethod| method.token == 0x0600_0205)
        .expect(
            "RangeAsync MoveNext MethodDef token 0x06000205 must be present in the baseline corpus",
        );
    assert!(
        is_unlowered_compiler_construct_refusal(&range_async.body),
        "RangeAsync MoveNext must carry the canonical unlowered compiler-construct refusal:\n{}",
        range_async.body
    );
    let observed: Vec<(u32, String)> = unlowered_compiler_construct_refusals(&methods);
    assert_eq!(
        observed,
        expected_unlowered_compiler_construct_refusals(),
        "the pinned unlowered compiler-construct refusal set changed"
    );
}

#[test]
fn compiler_construct_text_inside_a_string_does_not_skip_compiler_hosting() {
    let body: &str = concat!(
        "private void MoveNext()\n",
        "{\n",
        "    string note = \"disrobe: compiler-generated construct not lowered\";\n",
        "}\n"
    );
    assert!(!is_unlowered_compiler_construct_refusal(body));
    assert!(
        host_source(0, body).is_some(),
        "unlowered compiler-construct refusal text inside a string literal is ordinary recovered code"
    );
}

#[test]
fn sentinel_plus_malformed_live_code_does_not_skip_compiler_hosting() {
    let body: &str = concat!(
        "private void MoveNext()\n",
        "{\n",
        "    throw new System.NotSupportedException(\"disrobe: compiler-generated construct not lowered\");\n",
        "    this.__9__1_0 = ;\n",
        "}\n"
    );
    assert!(!is_unlowered_compiler_construct_refusal(body));
    assert!(
        host_source(0, body).is_some(),
        "a sentinel alongside malformed live code must reach compiler classification"
    );
}

#[cfg(windows)]
fn process_failure_without_diagnostic() -> std::process::Output {
    Command::new("cmd")
        .args(["/C", "exit", "1"])
        .output()
        .expect("run a process that exits without compiler diagnostics")
}

#[cfg(unix)]
fn process_failure_without_diagnostic() -> std::process::Output {
    Command::new("sh")
        .args(["-c", "exit 1"])
        .output()
        .expect("run a process that exits without compiler diagnostics")
}

#[cfg(any(windows, unix))]
#[test]
fn compiler_exit_failure_without_diagnostic_is_unclassified() {
    let output: std::process::Output = process_failure_without_diagnostic();
    let diagnostics: Vec<String> = Vec::new();
    assert!(!output.status.success());
    assert!(
        !compiler_succeeded(&output, &diagnostics),
        "a nonzero compiler exit without a parsed diagnostic is unclassified, not compiled"
    );
}

#[test]
fn movenext_bodies_recompile_against_csc() {
    require_dotnet("the MoveNext compiler gate");
    let asm: DecompiledAssembly = decompile();
    let methods: Vec<&StructuredMethod> = move_next_methods(&asm);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_movenext_recompile_oracle")
            .expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp);

    let total: usize = methods.len();
    let mut compiled: usize = 0;
    let mut refused: usize = 0;
    let mut unclassified: usize = 0;
    let mut failures: Vec<(usize, String)> = Vec::new();
    let observed_refusals: Vec<(u32, String)> = unlowered_compiler_construct_refusals(&methods);
    assert_eq!(
        observed_refusals,
        expected_unlowered_compiler_construct_refusals(),
        "the compiler host must exclude only the pinned unlowered compiler-construct refusals"
    );
    for (id, method) in methods.iter().enumerate() {
        let body: &str = &method.body;
        if is_unlowered_compiler_construct_refusal(body) {
            refused = refused.saturating_add(1);
            continue;
        }
        let Some(src): Option<String> = host_source(id, body) else {
            unclassified = unclassified.saturating_add(1);
            failures.push((id, "could not construct a compiler host".to_owned()));
            continue;
        };
        let output: std::process::Output = compile_output(&tmp, &format!("{PREAMBLE}{src}"));
        let diagnostics: Vec<String> = compiler_diagnostics(&output);
        if compiler_succeeded(&output, &diagnostics) {
            compiled = compiled.saturating_add(1);
        } else {
            unclassified = unclassified.saturating_add(1);
            let reason: String = diagnostics.first().cloned().unwrap_or_else(|| {
                format!(
                    "compiler exited with status {} without a parsed error",
                    output.status
                )
            });
            failures.push((id, reason));
        }
    }
    eprintln!(
        "MOVENEXT RECOMPILE: {compiled} compiled, {refused} unlowered compiler-construct refusals, {unclassified} unclassified / {total} total MoveNext bodies"
    );
    for (id, err) in &failures {
        eprintln!("  FAIL __Mover{id}: {err}");
    }
    assert!(
        compiled >= COMPILED_FLOOR,
        "MoveNext compiler baseline regressed: {compiled} compiled, {refused} unlowered compiler-construct refusals, {unclassified} unclassified / {total} total MoveNext bodies (compiled floor {COMPILED_FLOOR}). Failures:\n{}",
        failures
            .iter()
            .map(|(id, err): &(usize, String)| format!("  __Mover{id}: {err}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
    assert_eq!(
        refused,
        EXPECTED_UNLOWERED_COMPILER_CONSTRUCT_REFUSALS.len(),
        "only the pinned unlowered compiler-construct refusals may be excluded from compiler hosting"
    );
    assert_eq!(
        unclassified,
        0,
        "every non-refused MoveNext body must compile; failures:\n{}",
        failures
            .iter()
            .map(|(id, err): &(usize, String)| format!("  __Mover{id}: {err}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
    assert_eq!(
        compiled
            .saturating_add(refused)
            .saturating_add(unclassified),
        total,
        "every MoveNext body must be classified as compiled, refused, or unclassified"
    );
    assert!(
        failures.is_empty(),
        "non-refused MoveNext bodies must compile against csc; unclassified failures:\n{}",
        failures
            .iter()
            .map(|(id, err): &(usize, String)| format!("  __Mover{id}: {err}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
}
