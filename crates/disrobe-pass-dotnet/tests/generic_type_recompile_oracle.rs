#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

const GENERIC_TYPES: &[(&str, &str)] = &[
    ("Container", "T"),
    ("CountedList", "T"),
    ("FrozenSnapshot", "T"),
    ("CircularBuffer", "T"),
    ("GraphAdjacency", "T"),
    ("ObjectPool", "T"),
    ("FixedSlots", "T"),
    ("WeightedRandom", "T"),
    ("Cache", "TKey, TValue"),
    ("LruCache", "TKey, TValue"),
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

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = std::fs::read(manifest(DLL)).expect("read EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile")
}

fn declaring_short(body: &str) -> Option<String> {
    let first: &str = body.lines().next()?;
    let rest: &str = first.trim_start().strip_prefix("//")?.trim();
    rest.split_whitespace()
        .next()
        .map(|s: &str| s.rsplit('.').next().unwrap_or(s).to_owned())
}

fn is_generated(short: &str) -> bool {
    short.contains('<') || short.contains(">d__") || short.starts_with("<>")
}

fn has_placeholder_leak(line: &str) -> bool {
    let bytes: &[u8] = line.as_bytes();
    (0..bytes.len()).any(|i: usize| {
        if bytes[i] != b'!' {
            return false;
        }
        let digit_start: usize = if bytes.get(i + 1) == Some(&b'!') {
            i + 2
        } else {
            i + 1
        };
        let preceded_by_ident: bool = i
            .checked_sub(1)
            .and_then(|p: usize| bytes.get(p))
            .is_some_and(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_');
        !preceded_by_ident
            && bytes
                .get(digit_start)
                .is_some_and(|b: &u8| b.is_ascii_digit())
    })
}

#[test]
fn user_methods_carry_no_generic_placeholder_leak() {
    let asm: DecompiledAssembly = decompile();
    let mut offenders: Vec<String> = Vec::new();
    for m in &asm.methods {
        let first: &str = m.body.lines().next().unwrap_or_default();
        let generated: bool = declaring_short(&m.body).is_some_and(|s: String| is_generated(&s))
            || first.contains("compiler-generated")
            || first.contains("[record");
        if generated {
            continue;
        }
        if m.body.lines().any(has_placeholder_leak) {
            offenders.push(m.signature.lines().next().unwrap_or("").to_owned());
        }
    }
    assert!(
        offenders.is_empty(),
        "recovered user methods still leak raw generic-parameter tokens (!n / !!n):\n{}",
        offenders.join("\n")
    );
}

fn signature_header(body: &str) -> Option<(usize, String)> {
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

fn strip_visibility(decl: &str) -> String {
    let mut rest: &str = decl.trim_start();
    for kw in [
        "public ",
        "private protected ",
        "protected internal ",
        "private ",
        "protected ",
        "internal ",
        "static ",
    ] {
        if let Some(r) = rest.strip_prefix(kw) {
            rest = r;
        }
    }
    rest.to_owned()
}

fn rename_special(decl: &str) -> String {
    decl.replace(".ctor", "Ctor")
        .replace(".cctor", "Cctor")
        .replace("op_", "Op_")
}

fn this_members(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let mut rest: &str = line;
        while let Some(pos) = rest.find("this.") {
            let after: &str = &rest[pos + "this.".len()..];
            let len: usize = after
                .bytes()
                .take_while(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_')
                .count();
            if len > 0 {
                out.insert(after[..len].to_owned());
            }
            rest = &after[len.max(1)..];
        }
    }
    out
}

fn host_source(id: usize, body: &str, type_params: &str) -> Option<String> {
    let first: &str = body.lines().next().unwrap_or_default();
    if first.contains("[record") || first.contains("compiler-generated") {
        return None;
    }
    let (decl_line, decl): (usize, String) = signature_header(body)?;
    if decl.contains('<') && !decl.contains("=>") {
        return None;
    }
    let tail: String = body
        .lines()
        .skip(decl_line + 1)
        .collect::<Vec<&str>>()
        .join("\n");
    let normalized: String = rename_special(&strip_visibility(&decl));
    let stubs: String = this_members(body)
        .iter()
        .map(|m: &String| format!("    public dynamic {m} = null;"))
        .collect::<Vec<String>>()
        .join("\n");
    Some(format!(
        "public class __Host{id}<{type_params}>\n{{\n{stubs}\n    public {normalized}\n{tail}\n}}\n"
    ))
}

const PREAMBLE: &str = "using System;\nusing System.IO;\nusing System.Text;\nusing System.Threading;\nusing System.Collections;\nusing System.Collections.Generic;\nusing System.Collections.Concurrent;\nusing System.Linq;\nusing System.Threading.Tasks;\nusing System.Runtime.CompilerServices;\n\n";

fn write_project(dir: &Path) {
    let csproj: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <NoWarn>CS0168;CS0219;CS0162;CS0164;CS0649;CS1998;CS4014</NoWarn>\n  </PropertyGroup>\n  <ItemGroup>\n    <Reference Include=\"Microsoft.CSharp\" />\n  </ItemGroup>\n</Project>\n";
    std::fs::write(dir.join("oracle.csproj"), csproj).expect("write csproj");
}

fn compile_host(dir: &Path, src: &str) -> Vec<String> {
    std::fs::write(dir.join("host.cs"), format!("{PREAMBLE}{src}")).expect("write host source");
    let out: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("dotnet build");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&out.stderr).lines())
        .filter(|l: &&str| l.contains(": error "))
        .map(|l: &str| l.trim().to_owned())
        .collect()
}

const GENERIC_RECOMPILE_FLOOR: usize = 24;

#[test]
fn generic_type_methods_recompile_against_csc() {
    if !dotnet_available() {
        eprintln!("SKIP generic-type recompile oracle: no dotnet SDK on PATH");
        return;
    }
    let asm: DecompiledAssembly = decompile();
    let tmp: PathBuf = std::env::temp_dir().join("disrobe_generic_type_recompile_oracle");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    write_project(&tmp);

    let mut clean: usize = 0;
    let mut total: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for (id, m) in asm.methods.iter().enumerate() {
        let sm: &StructuredMethod = m;
        let Some(short): Option<String> = declaring_short(&sm.body) else {
            continue;
        };
        let Some((_, type_params)): Option<&(&str, &str)> = GENERIC_TYPES
            .iter()
            .find(|(name, _): &&(&str, &str)| *name == short)
        else {
            continue;
        };
        let Some(src): Option<String> = host_source(id, &sm.body, type_params) else {
            continue;
        };
        total += 1;
        let errs: Vec<String> = compile_host(&tmp, &src);
        if errs.is_empty() {
            clean += 1;
        } else {
            failures.push(format!(
                "  {} :: {}",
                sm.signature.lines().next().unwrap_or(""),
                errs.first().cloned().unwrap_or_default()
            ));
        }
    }
    eprintln!(
        "GENERIC-TYPE RECOMPILE ORACLE: {clean}/{total} generic-type methods compile clean against csc"
    );
    for f in &failures {
        eprintln!("{f}");
    }
    assert!(
        clean >= GENERIC_RECOMPILE_FLOOR,
        "generic-type recompile rate regressed below the floor: {clean}/{total} (floor {GENERIC_RECOMPILE_FLOOR})",
    );
}
