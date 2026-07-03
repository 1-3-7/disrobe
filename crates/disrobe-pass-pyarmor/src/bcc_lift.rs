use std::collections::BTreeMap;

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoAbi, disassemble, recover_leaf_function_abi,
};

use crate::error::{Error, Result};
use crate::v8v9::BccArch;

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_STRINGS: u64 = 0x20;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const MAX_FUNCTIONS: usize = 4096;
const MAX_DISASM_LINES: usize = 4096;
const MIN_STRING_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionId {
    pub entry_va: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoCFunction {
    pub id: FunctionId,
    pub signature: String,
    pub pseudo_c: String,
    pub size: u32,
    pub parameter_count: u32,
    pub modeled: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccLiftOutput {
    pub architecture: BccArch,
    pub text_base: u64,
    pub functions: BTreeMap<FunctionId, PseudoCFunction>,
    pub modeled_count: usize,
    pub unmodeled_count: usize,
    pub strings: Vec<String>,
    pub notes: Vec<String>,
}

struct ExecutableImage {
    base: u64,
    code: Vec<u8>,
    strings: Vec<String>,
}

pub fn lift_bcc_native(blob: &[u8], arch: BccArch) -> Result<BccLiftOutput> {
    if blob.is_empty() {
        return Err(Error::BccLiftEmptyBlob);
    }
    let Some(abi): Option<PseudoAbi> = arch_to_abi(arch) else {
        return Ok(BccLiftOutput {
            architecture: arch,
            text_base: 0,
            functions: BTreeMap::new(),
            modeled_count: 0,
            unmodeled_count: 0,
            strings: Vec::new(),
            notes: vec![format!(
                "BCC body targets {}; the in-crate pseudo-C lift models x86-64 only, so this AArch64 image is surfaced but not lifted",
                arch.label()
            )],
        });
    };

    let image: ExecutableImage = extract_executable_image(blob)?;
    let functions: Vec<PseudoCFunction> = lift_code_region(&image.code, image.base, abi);

    let mut modeled_count: usize = 0;
    let mut unmodeled_count: usize = 0;
    let mut map: BTreeMap<FunctionId, PseudoCFunction> = BTreeMap::new();
    for func in functions {
        if func.modeled {
            modeled_count += 1;
        } else {
            unmodeled_count += 1;
        }
        map.insert(func.id.clone(), func);
    }

    let mut notes: Vec<String> = Vec::new();
    if modeled_count == 0 && unmodeled_count > 0 {
        notes.push(
            "every discovered BCC function delegates to the PyArmor/CPython runtime dispatch table via indirect calls; native disassembly is surfaced per function, but the object semantics are resolved at load time and are not statically standalone-recompilable"
                .to_owned(),
        );
    }

    Ok(BccLiftOutput {
        architecture: arch,
        text_base: image.base,
        functions: map,
        modeled_count,
        unmodeled_count,
        strings: image.strings,
        notes,
    })
}

#[must_use]
pub fn lift_bcc_code_region(code: &[u8], base: u64, arch: BccArch) -> Vec<PseudoCFunction> {
    arch_to_abi(arch).map_or_else(Vec::new, |abi: PseudoAbi| lift_code_region(code, base, abi))
}

pub(crate) fn lift_code_region(code: &[u8], base: u64, abi: PseudoAbi) -> Vec<PseudoCFunction> {
    let Ok(insns): std::result::Result<Vec<DisasmInsn>, _> = disassemble(Arch::X86_64, base, code)
    else {
        return Vec::new();
    };
    if insns.is_empty() {
        return Vec::new();
    }
    let bounds: Vec<(usize, usize)> = discover_functions(&insns);
    let mut out: Vec<PseudoCFunction> = Vec::with_capacity(bounds.len());
    for (start_idx, end_idx) in bounds {
        let entry_va: u64 = insns[start_idx].address;
        let last: &DisasmInsn = &insns[end_idx - 1];
        let end_va: u64 = last.address + last.bytes.len() as u64;
        let size: u32 = u32::try_from(end_va.saturating_sub(entry_va)).unwrap_or(u32::MAX);
        let start_off: usize = usize::try_from(entry_va.saturating_sub(base)).unwrap_or(0);
        let end_off: usize = usize::try_from(end_va.saturating_sub(base)).unwrap_or(code.len());
        let slice: &[u8] = code.get(start_off..end_off).unwrap_or(&[]);
        out.push(render_function(
            slice,
            entry_va,
            size,
            abi,
            &insns[start_idx..end_idx],
        ));
    }
    out
}

fn render_function(
    slice: &[u8],
    entry_va: u64,
    size: u32,
    abi: PseudoAbi,
    insns: &[DisasmInsn],
) -> PseudoCFunction {
    let name: String = format!("sub_{entry_va:x}");
    match recover_leaf_function_abi(slice, entry_va, abi) {
        Ok(recovery) => {
            let parameter_count: u32 =
                u32::try_from(recovery.params.len() + recovery.fp_params.len()).unwrap_or(0);
            let pseudo_c: String = rename_recovered(&recovery, &name);
            let signature: String = extract_signature(&pseudo_c, &name);
            PseudoCFunction {
                id: FunctionId { entry_va, name },
                signature,
                pseudo_c,
                size,
                parameter_count,
                modeled: true,
                note: None,
            }
        }
        Err(e) => {
            let reason: String = format!("{e}");
            let pseudo_c: String = render_unmodeled(&name, entry_va, insns, &reason);
            PseudoCFunction {
                id: FunctionId {
                    entry_va,
                    name: name.clone(),
                },
                signature: format!("void {name}(void)"),
                pseudo_c,
                size,
                parameter_count: 0,
                modeled: false,
                note: Some(reason),
            }
        }
    }
}

fn rename_recovered(recovery: &LeafRecovery, name: &str) -> String {
    recovery
        .source
        .replacen("recovered(", &format!("{name}("), 1)
}

fn extract_signature(pseudo_c: &str, name: &str) -> String {
    let needle: String = format!("{name}(");
    pseudo_c
        .lines()
        .find(|line: &&str| line.contains(needle.as_str()))
        .map_or_else(
            || format!("uint64_t {name}(void)"),
            |line: &str| line.trim_end_matches(" {").trim().to_owned(),
        )
}

fn render_unmodeled(name: &str, entry_va: u64, insns: &[DisasmInsn], reason: &str) -> String {
    let mut out: String = String::new();
    push_format(
        &mut out,
        format_args!("/* {name} @ {entry_va:#x}: in-crate pseudo-C lift declined ({reason}).\n"),
    );
    out.push_str(
        "   BCC compiles CPython bytecode to native code that calls the PyArmor runtime dispatch\n",
    );
    out.push_str(
        "   table indirectly; the recovered semantics live behind load-time-resolved pointers and\n",
    );
    out.push_str(
        "   are not statically standalone-recompilable. Verified native disassembly follows. */\n",
    );
    push_format(&mut out, format_args!("void {name}(void) {{\n"));
    for (i, insn) in insns.iter().enumerate() {
        if i >= MAX_DISASM_LINES {
            push_format(
                &mut out,
                format_args!("    /* ... {} more instructions */\n", insns.len() - i),
            );
            break;
        }
        let rel: u64 = insn.address.saturating_sub(entry_va);
        if insn.operands.is_empty() {
            push_format(
                &mut out,
                format_args!("    /* +{rel:#06x}  {} */\n", insn.mnemonic),
            );
        } else {
            push_format(
                &mut out,
                format_args!(
                    "    /* +{rel:#06x}  {} {} */\n",
                    insn.mnemonic, insn.operands
                ),
            );
        }
    }
    out.push_str("}\n");
    out
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn discover_functions(insns: &[DisasmInsn]) -> Vec<(usize, usize)> {
    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut idx: usize = 0;
    let n: usize = insns.len();
    while idx < n && bounds.len() < MAX_FUNCTIONS {
        while idx < n && is_padding(&insns[idx]) {
            idx += 1;
        }
        if idx >= n {
            break;
        }
        let start: usize = idx;
        let mut max_branch_target: u64 = 0;
        let mut end: Option<usize> = None;
        let mut cursor: usize = idx;
        while cursor < n {
            let insn: &DisasmInsn = &insns[cursor];
            if let Some(target) = branch_target(insn) {
                max_branch_target = max_branch_target.max(target);
            }
            let terminates: bool = insn.address >= max_branch_target
                && (insn.mnemonic == "ret"
                    || (insn.mnemonic == "jmp" && branch_target(insn).is_some()));
            if terminates {
                end = Some(cursor + 1);
                break;
            }
            cursor += 1;
        }
        if let Some(e) = end {
            bounds.push((start, e));
            idx = e;
        } else {
            bounds.push((start, n));
            break;
        }
    }
    bounds
}

fn is_padding(insn: &DisasmInsn) -> bool {
    insn.mnemonic == "nop" || insn.mnemonic == "int3"
}

fn branch_target(insn: &DisasmInsn) -> Option<u64> {
    let is_branch: bool =
        insn.mnemonic == "jmp" || (insn.mnemonic.starts_with('j') && insn.mnemonic.len() <= 4);
    if !is_branch {
        return None;
    }
    parse_hex_operand(&insn.operands)
}

fn parse_hex_operand(operands: &str) -> Option<u64> {
    let trimmed: &str = operands.trim();
    let token: &str = trimmed.strip_prefix("short ").unwrap_or(trimmed).trim();
    if token.contains([' ', ',', '[']) {
        return None;
    }
    let body: &str = token.strip_suffix(['h', 'H']).unwrap_or(token);
    let body: &str = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    u64::from_str_radix(body, 16).ok()
}

const fn arch_to_abi(arch: BccArch) -> Option<PseudoAbi> {
    match arch {
        BccArch::WinX64 | BccArch::Other(_) => Some(PseudoAbi::MsX64),
        BccArch::LinuxX64 => Some(PseudoAbi::SysV),
        BccArch::DarwinArm64 => None,
    }
}

fn extract_executable_image(blob: &[u8]) -> Result<ExecutableImage> {
    if blob.len() >= 4 && blob[..4] == ELF_MAGIC {
        return parse_elf64(blob);
    }
    parse_via_object(blob)
}

fn parse_elf64(blob: &[u8]) -> Result<ExecutableImage> {
    if blob.len() < 64 || blob[4] != 2 || blob[5] != 1 {
        return Err(Error::BccLiftParse(
            "not a little-endian ELF64 relocatable object".to_owned(),
        ));
    }
    let e_shoff: usize = usize::try_from(read_u64(blob, 0x28)?).unwrap_or(usize::MAX);
    let e_shentsize: usize = usize::from(read_u16(blob, 0x3a)?);
    let e_shnum: usize = usize::from(read_u16(blob, 0x3c)?);
    if e_shentsize < 64 || e_shnum == 0 {
        return Err(Error::BccLiftParse(
            "degenerate ELF section table".to_owned(),
        ));
    }

    let mut best_exec: Option<(u64, usize, usize)> = None;
    let mut strings: Vec<String> = Vec::new();
    for i in 0..e_shnum {
        let sh: usize = e_shoff
            .checked_add(i.checked_mul(e_shentsize).ok_or_else(section_overflow)?)
            .ok_or_else(section_overflow)?;
        if sh.checked_add(64).is_none_or(|end: usize| end > blob.len()) {
            break;
        }
        let sh_type: u32 = read_u32(blob, sh + 4)?;
        let sh_flags: u64 = read_u64(blob, sh + 8)?;
        let sh_addr: u64 = read_u64(blob, sh + 16)?;
        let sh_offset: usize = usize::try_from(read_u64(blob, sh + 24)?).unwrap_or(usize::MAX);
        let sh_size: usize = usize::try_from(read_u64(blob, sh + 32)?).unwrap_or(usize::MAX);
        let Some(section): Option<&[u8]> = sh_offset
            .checked_add(sh_size)
            .and_then(|end: usize| blob.get(sh_offset..end))
        else {
            continue;
        };
        if sh_type == SHT_PROGBITS
            && sh_flags & SHF_EXECINSTR != 0
            && sh_flags & SHF_ALLOC != 0
            && best_exec.is_none_or(|(_, _, best): (u64, usize, usize)| sh_size > best)
        {
            best_exec = Some((sh_addr, sh_offset, sh_size));
        }
        if sh_flags & SHF_STRINGS != 0 {
            strings.extend(carve_c_strings(section));
        }
    }

    let Some((base, offset, size)): Option<(u64, usize, usize)> = best_exec else {
        return Err(Error::BccLiftParse(
            "no executable PROGBITS section in ELF image".to_owned(),
        ));
    };
    let code: Vec<u8> = blob
        .get(offset..offset + size)
        .ok_or_else(|| Error::BccLiftParse("executable section out of range".to_owned()))?
        .to_vec();
    strings.sort_unstable();
    strings.dedup();
    Ok(ExecutableImage {
        base,
        code,
        strings,
    })
}

fn parse_via_object(blob: &[u8]) -> Result<ExecutableImage> {
    use object::{Object as _, ObjectSection as _};
    let file: object::File<'_> =
        object::File::parse(blob).map_err(|e| Error::BccLiftParse(format!("{e}")))?;
    let mut best: Option<(u64, Vec<u8>)> = None;
    let mut strings: Vec<String> = Vec::new();
    for section in file.sections() {
        let Ok(data): std::result::Result<&[u8], _> = section.data() else {
            continue;
        };
        match section.kind() {
            object::SectionKind::Text
                if best
                    .as_ref()
                    .is_none_or(|(_, b): &(u64, Vec<u8>)| data.len() > b.len()) =>
            {
                best = Some((section.address(), data.to_vec()));
            }
            object::SectionKind::ReadOnlyString | object::SectionKind::ReadOnlyData => {
                strings.extend(carve_c_strings(data));
            }
            _ => {}
        }
    }
    let Some((base, code)): Option<(u64, Vec<u8>)> = best else {
        return Err(Error::BccLiftParse(
            "no text section in object image".to_owned(),
        ));
    };
    strings.sort_unstable();
    strings.dedup();
    Ok(ExecutableImage {
        base,
        code,
        strings,
    })
}

fn carve_c_strings(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for chunk in data.split(|b: &u8| *b == 0) {
        if chunk.len() >= MIN_STRING_LEN
            && chunk
                .iter()
                .all(|b: &u8| b.is_ascii_graphic() || *b == b' ')
        {
            out.push(String::from_utf8_lossy(chunk).into_owned());
        }
    }
    out
}

fn section_overflow() -> Error {
    Error::BccLiftParse("ELF section header offset overflow".to_owned())
}

fn read_u16(blob: &[u8], off: usize) -> Result<u16> {
    let bytes: [u8; 2] = blob
        .get(off..off + 2)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u16".to_owned()))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(blob: &[u8], off: usize) -> Result<u32> {
    let bytes: [u8; 4] = blob
        .get(off..off + 4)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u32".to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(blob: &[u8], off: usize) -> Result<u64> {
    let bytes: [u8; 8] = blob
        .get(off..off + 8)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u64".to_owned()))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_returns_specific_error() {
        let err: Error = lift_bcc_native(&[], BccArch::WinX64).unwrap_err();
        assert!(matches!(err, Error::BccLiftEmptyBlob));
    }

    #[test]
    fn aarch64_image_is_surfaced_but_not_lifted() {
        let blob: Vec<u8> = vec![0u8; 64];
        let out: BccLiftOutput = lift_bcc_native(&blob, BccArch::DarwinArm64).unwrap();
        assert_eq!(out.modeled_count, 0);
        assert!(out.functions.is_empty());
        assert!(out.notes.iter().any(|n: &String| n.contains("x86-64 only")));
    }

    #[test]
    fn non_elf_garbage_errors_with_parse() {
        let blob: Vec<u8> = vec![0x11u8; 128];
        let err: Error = lift_bcc_native(&blob, BccArch::WinX64).unwrap_err();
        assert!(matches!(err, Error::BccLiftParse(_)));
    }

    #[test]
    fn arch_maps_to_expected_abi() {
        assert!(matches!(
            arch_to_abi(BccArch::WinX64),
            Some(PseudoAbi::MsX64)
        ));
        assert!(matches!(
            arch_to_abi(BccArch::LinuxX64),
            Some(PseudoAbi::SysV)
        ));
        assert!(arch_to_abi(BccArch::DarwinArm64).is_none());
    }

    #[test]
    fn parse_hex_operand_reads_near_targets() {
        assert_eq!(parse_hex_operand("0x1b0"), Some(0x1b0));
        assert_eq!(parse_hex_operand("short 0x7d"), Some(0x7d));
        assert_eq!(parse_hex_operand("1ach"), Some(0x1ac));
        assert_eq!(parse_hex_operand("qword ptr [rax+8]"), None);
        assert_eq!(parse_hex_operand("rax"), None);
    }

    #[test]
    fn discover_functions_splits_ret_and_padding() {
        let mc: &[u8] = &[0x48, 0x01, 0xd0, 0xc3, 0x90, 0x90, 0x48, 0x29, 0xd0, 0xc3];
        let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, 0x1000, mc).unwrap();
        let bounds: Vec<(usize, usize)> = discover_functions(&insns);
        assert_eq!(bounds.len(), 2, "two ret-terminated functions expected");
    }

    #[test]
    fn leaf_add_lifts_and_is_modeled() {
        let mc: &[u8] = &[0x48, 0x8d, 0x04, 0x37, 0xc3];
        let funcs: Vec<PseudoCFunction> = lift_code_region(mc, 0x2000, PseudoAbi::SysV);
        assert_eq!(funcs.len(), 1);
        assert!(
            funcs[0].modeled,
            "lea-based add must lift into the leaf class"
        );
        assert!(funcs[0].pseudo_c.contains("sub_2000("));
        assert!(!funcs[0].pseudo_c.contains("recovered("));
    }

    #[test]
    fn indirect_call_body_is_surfaced_as_unmodeled_disasm() {
        let mc: &[u8] = &[0xff, 0x50, 0x08, 0xc3];
        let funcs: Vec<PseudoCFunction> = lift_code_region(mc, 0x3000, PseudoAbi::MsX64);
        assert_eq!(funcs.len(), 1);
        assert!(!funcs[0].modeled);
        assert!(funcs[0].pseudo_c.contains("call"));
        assert!(funcs[0].note.is_some());
    }

    #[test]
    fn carve_c_strings_keeps_printable_runs() {
        let data: &[u8] = b"ab\0hello\0\x01\x02";
        let strings: Vec<String> = carve_c_strings(data);
        assert_eq!(strings, vec!["hello".to_owned()]);
    }
}
