#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind};
use serde::Serialize;

pub(crate) fn decompile(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let resolved: Option<PathBuf> = locate_ghidra_headless();
    let Some(ghidra): Option<PathBuf> = resolved else {
        return Err(miette::miette!(
            "DR-NATIVE-0001: ghidra-headless not on PATH (set GHIDRA_HOME or run `disrobe install-deps ghidra`). Native decompile uses Ghidra-headless to lift PE/ELF/Mach-O binaries to a pseudo-C-source."
        ));
    };
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-native-decompiled")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0002: cannot create out dir: {e}"))?;

    let project_dir: PathBuf = out_dir.join("ghidra-project");
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0003: cannot create ghidra project dir: {e}"))?;

    let script_dir: PathBuf = out_dir.join("scripts");
    std::fs::create_dir_all(&script_dir)
        .map_err(|e| miette::miette!("DR-NATIVE-0008: cannot create scripts dir: {e}"))?;
    let script_name: &str = "DisrobeDecompileScript.java";
    let script_path: PathBuf = script_dir.join(script_name);
    let decompile_out: PathBuf = out_dir.join(format!("{stem}.decompiled.c"));
    write_decompile_script(&script_path, &decompile_out)?;

    let output: Output = Command::new(&ghidra)
        .arg(&project_dir)
        .arg("disrobe-native")
        .arg("-import")
        .arg(&input)
        .arg("-postScript")
        .arg(script_name)
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-deleteProject")
        .arg("-overwrite")
        .arg("-noanalysis")
        .output()
        .map_err(|e| miette::miette!("DR-NATIVE-0004: ghidra-headless spawn failed: {e}"))?;

    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let decompile_present: bool = decompile_out.is_file();
    let decompile_size: u64 = if decompile_present {
        std::fs::metadata(&decompile_out).map_or(0, |m| m.len())
    } else {
        0
    };
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.native.decompile/v0",
        "input": input.display().to_string(),
        "ghidra_headless": ghidra.display().to_string(),
        "exit_code": output.status.code(),
        "stdout_tail": tail_bytes(&stdout, 4096),
        "stderr_tail": tail_bytes(&stderr, 4096),
        "out_dir": out_dir.display().to_string(),
        "decompile_path": decompile_out.display().to_string(),
        "decompile_present": decompile_present,
        "decompile_size_bytes": decompile_size,
    });
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-NATIVE-0005: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0006: cannot write manifest: {e}"))?;

    if !output.status.success() {
        return Err(miette::miette!(
            "DR-NATIVE-0007: ghidra-headless exited with status {:?}; see {}",
            output.status.code(),
            manifest_path.display()
        ));
    }
    println!("native decompile: OK");
    println!("  input:        {}", input.display());
    println!("  ghidra:       {}", ghidra.display());
    println!("  out dir:      {}", out_dir.display());
    println!("  decompile:    {}", decompile_out.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn write_decompile_script(script_path: &Path, decompile_out: &Path) -> miette::Result<()> {
    let escaped: String = decompile_out.display().to_string().replace('\\', "\\\\");
    let body: String = format!(
        "import java.io.File;\nimport java.io.FileWriter;\nimport java.io.PrintWriter;\nimport ghidra.app.script.GhidraScript;\nimport ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.Function;\nimport ghidra.program.model.listing.FunctionIterator;\nimport ghidra.util.task.ConsoleTaskMonitor;\n\npublic class DisrobeDecompileScript extends GhidraScript {{\n    @Override\n    public void run() throws Exception {{\n        DecompInterface ifc = new DecompInterface();\n        ifc.openProgram(currentProgram);\n        File out = new File(\"{escaped}\");\n        out.getParentFile().mkdirs();\n        PrintWriter pw = new PrintWriter(new FileWriter(out));\n        try {{\n            FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);\n            for (Function f : fns) {{\n                if (f.isThunk() || f.isExternal()) continue;\n                DecompileResults r = ifc.decompileFunction(f, 60, new ConsoleTaskMonitor());\n                if (r != null && r.getDecompiledFunction() != null) {{\n                    pw.println(\"// FUNCTION \" + f.getName() + \" @ \" + f.getEntryPoint().toString());\n                    pw.println(r.getDecompiledFunction().getC());\n                    pw.println();\n                }}\n            }}\n        }} finally {{\n            pw.close();\n            ifc.dispose();\n        }}\n    }}\n}}\n"
    );
    std::fs::write(script_path, body.as_bytes()).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0009: cannot write decompile script {}: {e}",
            script_path.display()
        )
    })
}

pub(crate) fn symbols(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-NATIVE-0010: cannot read input: {e}"))?;
    let dump: SymbolDump = dump_symbols(&bytes, &input)?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("native-symbols")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.symbols.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0011: cannot create out dir: {e}"))?;
    }
    let buf: Vec<u8> = serde_json::to_vec_pretty(&dump)
        .map_err(|e| miette::miette!("DR-NATIVE-0012: serialize: {e}"))?;
    std::fs::write(&out_path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0013: cannot write symbols: {e}"))?;
    println!("native symbols: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {}", dump.format);
    println!("  arch:         {}", dump.arch);
    println!("  exports:      {}", dump.exports.len());
    println!("  imports:      {}", dump.imports.len());
    println!("  sections:     {}", dump.sections.len());
    println!("  segments:     {}", dump.segments.len());
    println!("  debug_info:   {}", dump.debug_info.present);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

#[derive(Debug, Serialize)]
struct SymbolDump {
    schema: &'static str,
    input: String,
    format: String,
    arch: String,
    entry: u64,
    is_64: bool,
    exports: Vec<SymbolRow>,
    imports: Vec<ImportRow>,
    sections: Vec<SectionRow>,
    segments: Vec<SegmentRow>,
    debug_info: DebugInfoSummary,
}

#[derive(Debug, Serialize)]
struct SymbolRow {
    name: String,
    address: u64,
    size: u64,
    kind: String,
    section: Option<String>,
}

#[derive(Debug, Serialize)]
struct ImportRow {
    name: String,
    library: Option<String>,
}

#[derive(Debug, Serialize)]
struct SectionRow {
    index: usize,
    name: String,
    address: u64,
    size: u64,
    kind: String,
    flags: String,
}

#[derive(Debug, Serialize)]
struct SegmentRow {
    name: Option<String>,
    address: u64,
    size: u64,
}

#[derive(Debug, Serialize)]
struct DebugInfoSummary {
    present: bool,
    sections: Vec<String>,
}

fn dump_symbols(bytes: &[u8], input: &Path) -> miette::Result<SymbolDump> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|e| miette::miette!("DR-NATIVE-0020: object parse failed: {e}"))?;
    let format: &'static str = match file.format() {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::Coff => "coff",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Wasm => "wasm",
        object::BinaryFormat::Xcoff => "xcoff",
        _ => "unknown",
    };
    let arch: String = format!("{:?}", file.architecture()).to_lowercase();
    let entry: u64 = file.entry();
    let is_64: bool = file.is_64();

    let mut exports: Vec<SymbolRow> = Vec::new();
    let section_names: BTreeMap<usize, String> = file
        .sections()
        .filter_map(|s| s.name().ok().map(|n| (s.index().0, n.to_owned())))
        .collect();
    for symbol in file.symbols() {
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let section: Option<String> = match symbol.section() {
            object::SymbolSection::Section(idx) => section_names.get(&idx.0).cloned(),
            _ => None,
        };
        exports.push(SymbolRow {
            name: name.to_owned(),
            address: symbol.address(),
            size: symbol.size(),
            kind: format!("{:?}", symbol.kind()).to_lowercase(),
            section,
        });
    }
    for symbol in file.dynamic_symbols() {
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let section: Option<String> = match symbol.section() {
            object::SymbolSection::Section(idx) => section_names.get(&idx.0).cloned(),
            _ => None,
        };
        exports.push(SymbolRow {
            name: name.to_owned(),
            address: symbol.address(),
            size: symbol.size(),
            kind: format!("{:?}", symbol.kind()).to_lowercase(),
            section,
        });
    }

    let mut imports: Vec<ImportRow> = Vec::new();
    if let Ok(import_iter) = file.imports() {
        for imp in import_iter {
            imports.push(ImportRow {
                name: String::from_utf8_lossy(imp.name()).into_owned(),
                library: Some(String::from_utf8_lossy(imp.library()).into_owned())
                    .filter(|s| !s.is_empty()),
            });
        }
    }

    let mut sections: Vec<SectionRow> = Vec::new();
    let mut debug_sections: Vec<String> = Vec::new();
    for (i, section) in file.sections().enumerate() {
        let name: String = section.name().map(str::to_owned).unwrap_or_default();
        let kind_label: String = format!("{:?}", section.kind()).to_lowercase();
        let flags_label: String = section_flags_label(section.flags());
        if matches!(
            section.kind(),
            SectionKind::Debug | SectionKind::DebugString
        ) || name.starts_with(".debug")
            || name.starts_with("__debug")
            || name.starts_with(".zdebug")
        {
            debug_sections.push(name.clone());
        }
        sections.push(SectionRow {
            index: i,
            name,
            address: section.address(),
            size: section.size(),
            kind: kind_label,
            flags: flags_label,
        });
    }

    let mut segments: Vec<SegmentRow> = Vec::new();
    for seg in file.segments() {
        segments.push(SegmentRow {
            name: seg.name().ok().flatten().map(str::to_owned),
            address: seg.address(),
            size: seg.size(),
        });
    }

    let debug_info: DebugInfoSummary = DebugInfoSummary {
        present: !debug_sections.is_empty(),
        sections: debug_sections,
    };

    Ok(SymbolDump {
        schema: "disrobe.native.symbols/v0",
        input: input.display().to_string(),
        format: format.to_owned(),
        arch,
        entry,
        is_64,
        exports,
        imports,
        sections,
        segments,
        debug_info,
    })
}

fn section_flags_label(flags: SectionFlags) -> String {
    match flags {
        SectionFlags::None => "none".to_owned(),
        SectionFlags::Elf { sh_flags } => format!("elf:0x{sh_flags:x}"),
        SectionFlags::MachO { flags } => format!("macho:0x{flags:x}"),
        SectionFlags::Coff { characteristics } => format!("coff:0x{characteristics:x}"),
        SectionFlags::Xcoff { s_flags } => format!("xcoff:0x{s_flags:x}"),
        _ => "other".to_owned(),
    }
}

fn locate_ghidra_headless() -> Option<PathBuf> {
    let candidates: [&str; 2] = if cfg!(windows) {
        ["analyzeHeadless.bat", "analyzeHeadless"]
    } else {
        ["analyzeHeadless", "analyzeHeadless.bat"]
    };
    for name in candidates {
        if let Some(found) = which_on_path(name) {
            return Some(found);
        }
    }
    if let Ok(home) = std::env::var("GHIDRA_HOME") {
        let base: PathBuf = PathBuf::from(home);
        for sub in ["support/analyzeHeadless", "support/analyzeHeadless.bat"] {
            let p: PathBuf = base.join(sub);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate: PathBuf = dir.join(exe);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn tail_bytes(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let start: usize = s.len() - n;
    let boundary: usize = (start..s.len())
        .find(|i| s.is_char_boundary(*i))
        .unwrap_or(start);
    s[boundary..].to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn locate_returns_none_when_path_empty() {
        let prev: Option<std::ffi::OsString> = std::env::var_os("PATH");
        let prev_home: Option<String> = std::env::var("GHIDRA_HOME").ok();
        unsafe {
            std::env::set_var("PATH", "");
            std::env::remove_var("GHIDRA_HOME");
        }
        let result: Option<PathBuf> = locate_ghidra_headless();
        unsafe {
            if let Some(p) = prev {
                std::env::set_var("PATH", p);
            } else {
                std::env::remove_var("PATH");
            }
            if let Some(h) = prev_home {
                std::env::set_var("GHIDRA_HOME", h);
            }
        }
        assert!(result.is_none());
    }

    #[test]
    fn tail_bytes_short_returns_input() {
        assert_eq!(tail_bytes("hello", 100), "hello");
    }

    #[test]
    fn tail_bytes_long_returns_suffix() {
        let s: String = "x".repeat(10_000);
        let cut: String = tail_bytes(&s, 100);
        assert_eq!(cut.len(), 100);
    }
}
