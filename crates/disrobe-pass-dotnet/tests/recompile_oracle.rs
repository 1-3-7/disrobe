#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

const FIXTURE_DLL: &str = "../../corpus/dotnet/constructs/Constructs.dll";

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

#[derive(Debug, Clone)]
struct HostMethod {
    id: usize,
    declaring_type: String,
    user_authored: bool,
    source: String,
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
        }
    }
    rest.strip_prefix("static ").unwrap_or(rest).to_owned()
}

fn rename_special(decl: &str) -> String {
    decl.replace(".ctor", "Ctor")
        .replace(".cctor", "Cctor")
        .replace("<Clone>$", "CloneDollar")
        .replace("op_", "Op_")
}

fn host_for(id: usize, body: &str) -> Option<HostMethod> {
    let declaring_type: String = declaring_type_of(body)?;
    let (decl_line, decl): (usize, String) = signature_header(body)?;
    let body_tail: String = body
        .lines()
        .skip(decl_line + 1)
        .collect::<Vec<&str>>()
        .join("\n");
    let normalized_decl: String = rename_special(&strip_visibility(&decl));
    let is_static_self: bool = declaring_type.ends_with("Constructs");
    let host: String = if is_static_self {
        format!(
            "public static class __Host{id} {{\n    public static {normalized_decl}\n{body_tail}\n}}\n"
        )
    } else {
        format!(
            "public class __Host{id} : global::{declaring_type} {{\n    public new {normalized_decl}\n{body_tail}\n}}\n"
        )
    };
    let first_line: &str = body.lines().next().unwrap_or_default();
    let user_authored: bool = !is_compiler_generated_type(&declaring_type)
        && !first_line.contains("[record")
        && !first_line.contains("compiler-generated");
    Some(HostMethod {
        id,
        declaring_type,
        user_authored,
        source: host,
    })
}

const PREAMBLE: &str = "using System;\nusing System.Text;\nusing System.Collections.Generic;\nusing System.Linq;\nusing System.Threading.Tasks;\nusing System.Runtime.CompilerServices;\nusing Sample;\n\n";

fn write_project(dir: &Path, dll: &Path) {
    let csproj: String = format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <AllowUnsafeBlocks>false</AllowUnsafeBlocks>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n  </PropertyGroup>\n  <ItemGroup>\n    <Reference Include=\"Constructs\"><HintPath>{}</HintPath></Reference>\n  </ItemGroup>\n</Project>\n",
        dll.display()
    );
    std::fs::write(dir.join("oracle.csproj"), csproj).expect("write csproj");
}

fn compile_host(dir: &Path, host: &HostMethod) -> Vec<String> {
    let src: String = format!("{PREAMBLE}{}", host.source);
    std::fs::write(dir.join("host.cs"), src).expect("write host source");
    let out: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("dotnet build");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l: &&str| l.contains(": error "))
        .map(|l: &str| l.trim().to_owned())
        .collect()
}

fn errors_per_host(dir: &Path, dll: &Path, hosts: &[HostMethod]) -> BTreeMap<usize, Vec<String>> {
    write_project(dir, dll);
    let mut map: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for h in hosts {
        let errs: Vec<String> = compile_host(dir, h);
        if !errs.is_empty() {
            map.insert(h.id, errs);
        }
    }
    map
}

fn decompile_fixture() -> DecompiledAssembly {
    let bytes: Vec<u8> = std::fs::read(manifest(FIXTURE_DLL)).expect("read fixture dll");
    decompile_assembly(&bytes).expect("decompile fixture")
}

struct OracleReport {
    user_pass: usize,
    user_total: usize,
    gen_hosts: usize,
    failures: Vec<(usize, String, String)>,
}

fn run_oracle() -> Option<OracleReport> {
    if !dotnet_available() {
        return None;
    }
    let asm: DecompiledAssembly = decompile_fixture();
    let hosts: Vec<HostMethod> = asm
        .methods
        .iter()
        .enumerate()
        .filter_map(
            |(i, m): (usize, &disrobe_pass_dotnet::structurize::StructuredMethod)| {
                host_for(i, &m.body)
            },
        )
        .collect();
    let gen_hosts: usize = hosts.iter().filter(|h| !h.user_authored).count();
    let user_hosts: Vec<HostMethod> = hosts.into_iter().filter(|h| h.user_authored).collect();
    let tmp: PathBuf = std::env::temp_dir().join("disrobe_recompile_oracle");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    let dll: PathBuf = manifest(FIXTURE_DLL)
        .canonicalize()
        .expect("canonicalize dll");
    let errs: BTreeMap<usize, Vec<String>> = errors_per_host(&tmp, &dll, &user_hosts);

    let user_total: usize = user_hosts.len();
    let user_pass: usize = user_hosts
        .iter()
        .filter(|h| !errs.contains_key(&h.id))
        .count();
    let failures: Vec<(usize, String, String)> = user_hosts
        .iter()
        .filter_map(|h| {
            errs.get(&h.id).map(|es: &Vec<String>| {
                (
                    h.id,
                    h.declaring_type.clone(),
                    es.first().cloned().unwrap_or_default(),
                )
            })
        })
        .collect();
    Some(OracleReport {
        user_pass,
        user_total,
        gen_hosts,
        failures,
    })
}

const RECOMPILE_FLOOR: usize = 6;

#[test]
fn user_method_recompile_rate_holds_or_climbs() {
    let Some(report): Option<OracleReport> = run_oracle() else {
        eprintln!("SKIP recompile oracle: no dotnet SDK on PATH");
        return;
    };
    eprintln!(
        "RECOMPILE ORACLE (user-authored methods): {}/{} compile clean against csc ({} compiler-generated hosts graded for reading, not recompile)",
        report.user_pass, report.user_total, report.gen_hosts
    );
    for (id, ty, err) in &report.failures {
        eprintln!("  FAIL __Host{id} ({ty}): {err}");
    }
    assert!(
        report.user_pass >= RECOMPILE_FLOOR,
        "user-method recompile rate regressed below the floor: {}/{} (floor {RECOMPILE_FLOOR}). Failures:\n{}",
        report.user_pass,
        report.user_total,
        report
            .failures
            .iter()
            .map(|(id, ty, err): &(usize, String, String)| format!("  __Host{id} ({ty}): {err}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
}
