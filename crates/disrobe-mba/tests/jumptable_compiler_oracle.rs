#![cfg(feature = "smt-solver")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_mba::{
    Endian, EntryKind, IndexBound, IndirectSite, JumpTableResolution, PathConstraint, Perms,
    Section, SectionMap, SuccessorKind, TableForm, resolve_jump_table,
};

const SWITCH_SOURCE: &str = "#include <stdio.h>\n\
__attribute__((noinline)) int pick(int x, int a, int b) {\n\
    switch (x) {\n\
        case 0: return a + 1;\n\
        case 1: return a - b;\n\
        case 2: return a * b;\n\
        case 3: return a ^ 7;\n\
        case 4: return b + 3;\n\
        case 5: return a | b;\n\
        case 6: return a & b;\n\
        case 7: return a % (b + 1);\n\
        default: return -1;\n\
    }\n\
}\n\
int main(int argc, char **argv) {\n\
    int s = 0;\n\
    for (int i = 0; i < argc + 8; i++) s += pick(i, argc, i);\n\
    printf(\"%d\\n\", s);\n\
    return 0;\n\
}\n";

fn tool_present(tool: &str, probe: &str) -> bool {
    Command::new(tool)
        .arg(probe)
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success())
}

fn gcc_is_x86_64() -> bool {
    let Ok(out): Result<std::process::Output, _> = Command::new("gcc").arg("-dumpmachine").output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains("x86_64")
}

fn parse_hex(text: &str) -> Option<u64> {
    let trimmed: &str = text.trim();
    let body: &str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(body, 16).ok()
}

struct Disasm {
    insn_starts: BTreeSet<u64>,
    pick: Vec<Instruction>,
}

struct Instruction {
    mnemonic: String,
    operands: String,
    comment: Option<String>,
}

fn parse_disasm(text: &str) -> Disasm {
    let mut insn_starts: BTreeSet<u64> = BTreeSet::new();
    let mut pick: Vec<Instruction> = Vec::new();
    let mut in_pick: bool = false;
    for raw in text.lines() {
        if raw.contains(">:") {
            in_pick = raw.contains("<pick>:");
            continue;
        }
        let fields: Vec<&str> = raw.split('\t').collect();
        let head: &str = fields.first().copied().unwrap_or_default();
        let mnemonic_field: &str = fields.get(2).copied().unwrap_or_default();
        let Some(colon): Option<usize> = head.find(':') else {
            continue;
        };
        let Some(address): Option<u64> = parse_hex(&head[..colon]) else {
            continue;
        };
        let body: &str = mnemonic_field.trim();
        if body.is_empty() {
            continue;
        }
        insn_starts.insert(address);
        if !in_pick {
            continue;
        }
        let (ops_part, comment): (&str, Option<String>) = match body.split_once('#') {
            Some((ops, note)) => (ops, Some(note.trim().to_owned())),
            None => (body, None),
        };
        let mut tokens = ops_part.split_whitespace();
        let mnemonic: String = tokens.next().unwrap_or_default().to_owned();
        let operands: String = tokens.collect::<Vec<&str>>().join(" ");
        pick.push(Instruction {
            mnemonic,
            operands,
            comment,
        });
    }
    Disasm { insn_starts, pick }
}

struct SectionBytes {
    base: u64,
    bytes: Vec<u8>,
}

fn parse_section_bytes(text: &str) -> Option<SectionBytes> {
    let mut base: Option<u64> = None;
    let mut bytes: Vec<u8> = Vec::new();
    for raw in text.lines() {
        let line: &str = raw.trim();
        let mut fields = line.split_whitespace();
        let Some(addr_field): Option<&str> = fields.next() else {
            continue;
        };
        let Some(addr): Option<u64> = parse_hex(addr_field) else {
            continue;
        };
        let groups: Vec<&str> = fields
            .take(4)
            .take_while(|group: &&str| group.chars().all(|ch: char| ch.is_ascii_hexdigit()))
            .collect();
        if groups.is_empty() {
            continue;
        }
        if base.is_none() {
            base = Some(addr);
        }
        for group in groups {
            let mut cursor: usize = 0;
            while cursor + 2 <= group.len() {
                let Some(byte): Option<u8> =
                    u8::from_str_radix(&group[cursor..cursor + 2], 16).ok()
                else {
                    break;
                };
                bytes.push(byte);
                cursor += 2;
            }
        }
    }
    base.map(|value: u64| SectionBytes { base: value, bytes })
}

struct SwitchSite {
    table_base: u64,
    bound: u64,
    default_target: u64,
}

fn recover_site(disasm: &Disasm) -> Option<SwitchSite> {
    let mut bound: Option<u64> = None;
    let mut default_target: Option<u64> = None;
    let mut table_base: Option<u64> = None;
    let mut relative_scale_four: bool = false;
    let mut last_cmp: Option<u64> = None;
    for instr in &disasm.pick {
        if instr.mnemonic == "cmp"
            && let Some((imm, _)) = instr.operands.split_once(',')
        {
            last_cmp = parse_hex(imm.trim_start_matches('$'));
        }
        if instr.mnemonic == "ja" {
            bound = last_cmp;
            default_target = instr.operands.split_whitespace().next().and_then(parse_hex);
        }
        if instr.mnemonic == "lea"
            && instr.operands.contains("(%rip)")
            && let Some(note) = &instr.comment
        {
            table_base = note.split_whitespace().next().and_then(parse_hex);
        }
        if (instr.mnemonic == "movslq" || instr.mnemonic == "movsxd")
            && instr.operands.contains(",4)")
        {
            relative_scale_four = true;
        }
    }
    if !relative_scale_four {
        return None;
    }
    Some(SwitchSite {
        table_base: table_base?,
        bound: bound?,
        default_target: default_target?,
    })
}

fn build_sections(disasm: &Disasm, rdata: &SectionBytes) -> SectionMap {
    let low: u64 = disasm.insn_starts.iter().next().copied().unwrap_or(0);
    let high: u64 = disasm
        .insn_starts
        .iter()
        .next_back()
        .copied()
        .unwrap_or(low);
    let span: usize = (high - low + 32) as usize;
    let code: Section = Section::new(low, vec![0u8; span], Perms::code(), false)
        .with_insn_starts(disasm.insn_starts.clone());
    let ro: Section = Section::new(rdata.base, rdata.bytes.clone(), Perms::ro(), true);
    SectionMap::new(vec![code, ro])
}

const fn relative_form(table_base: u64) -> TableForm {
    TableForm {
        table_base,
        stride: 4,
        entry_bytes: 4,
        endian: Endian::Little,
        entry: EntryKind::RelativeOffset {
            addend_base: table_base,
            signed: true,
            shift: 0,
        },
        case_base: 0,
    }
}

fn objdump(exe: &Path, args: &[&str]) -> Option<String> {
    let mut command: Command = Command::new("objdump");
    command.args(args).arg(exe);
    let out: std::process::Output = command.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn unique_dir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ticket: u64 = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_jt_{}_{ticket}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn gcc_o2_switch_resolves_against_objdump_ground_truth() {
    if !tool_present("gcc", "-dumpmachine") || !tool_present("objdump", "--version") {
        eprintln!("skip: gcc/objdump not on PATH");
        return;
    }
    if !gcc_is_x86_64() {
        eprintln!("skip: gcc is not an x86_64 target");
        return;
    }
    let dir: PathBuf = unique_dir();
    let source: PathBuf = dir.join("sw.c");
    let exe: PathBuf = dir.join("sw.exe");
    if std::fs::write(&source, SWITCH_SOURCE).is_err() {
        eprintln!("skip: cannot write source");
        return;
    }
    let compiled: bool = Command::new("gcc")
        .args(["-O2", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&exe)
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success());
    if !compiled {
        eprintln!("skip: gcc did not produce an executable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (Some(disasm_text), Some(rdata_text)): (Option<String>, Option<String>) = (
        objdump(&exe, &["-d"]),
        objdump(&exe, &["-s", "-j", ".rdata"]),
    ) else {
        eprintln!("skip: objdump failed");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let _ = std::fs::remove_dir_all(&dir);

    let disasm: Disasm = parse_disasm(&disasm_text);
    let Some(rdata): Option<SectionBytes> = parse_section_bytes(&rdata_text) else {
        eprintln!("skip: could not read .rdata");
        return;
    };
    let Some(site): Option<SwitchSite> = recover_site(&disasm) else {
        eprintln!("skip: jump-table dispatch pattern not recognized in this codegen");
        return;
    };

    let sections: SectionMap = build_sections(&disasm, &rdata);
    let indirect: IndirectSite = IndirectSite {
        form: relative_form(site.table_base),
        path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(site.bound)]),
        default_target: Some(site.default_target),
    };
    let resolution: JumpTableResolution = resolve_jump_table(&indirect, &sections);
    assert!(
        !resolution.is_abstain(),
        "a real gcc -O2 switch must resolve: {resolution:?}"
    );
    let cases: Vec<_> = resolution.cases();
    assert_eq!(
        cases.len() as u64,
        site.bound + 1,
        "one recovered case per switch label"
    );
    for successor in &cases {
        assert!(
            disasm.insn_starts.contains(&successor.target),
            "recovered target {:#x} is a real instruction boundary per objdump",
            successor.target
        );
    }
    let default_edges: Vec<_> = resolution
        .successors()
        .iter()
        .filter(|successor| successor.kind == SuccessorKind::Default)
        .collect();
    assert_eq!(default_edges.len(), 1);
    assert_eq!(default_edges[0].target, site.default_target);

    let unbounded: IndirectSite = IndirectSite {
        form: relative_form(site.table_base),
        path: PathConstraint::new(4, Vec::new()),
        default_target: Some(site.default_target),
    };
    assert!(
        resolve_jump_table(&unbounded, &sections).is_abstain(),
        "with no bounds check the index is unbounded and must abstain"
    );

    let corrupt: SectionMap = corrupt_first_entry(&disasm, &rdata, &site);
    assert!(
        resolve_jump_table(&indirect, &corrupt).is_abstain(),
        "a table entry redirected mid-instruction must trip the completeness gate"
    );
}

fn corrupt_first_entry(disasm: &Disasm, rdata: &SectionBytes, site: &SwitchSite) -> SectionMap {
    let mut bytes: Vec<u8> = rdata.bytes.clone();
    let offset: usize = (site.table_base - rdata.base) as usize;
    if offset + 4 <= bytes.len() {
        let mut raw: [u8; 4] = [0u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        let bumped: u32 = i32::from_le_bytes(raw).wrapping_add(1) as u32;
        bytes[offset..offset + 4].copy_from_slice(&bumped.to_le_bytes());
    }
    let low: u64 = disasm.insn_starts.iter().next().copied().unwrap_or(0);
    let high: u64 = disasm
        .insn_starts
        .iter()
        .next_back()
        .copied()
        .unwrap_or(low);
    let span: usize = (high - low + 32) as usize;
    let code: Section = Section::new(low, vec![0u8; span], Perms::code(), false)
        .with_insn_starts(disasm.insn_starts.clone());
    let ro: Section = Section::new(rdata.base, bytes, Perms::ro(), true);
    SectionMap::new(vec![code, ro])
}
