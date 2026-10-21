use disrobe_core::neutralize::{Anchor, NeutralizationPlan, Patch, Refusal, RuntimeCheck};
use serde::{Deserialize, Serialize};

use crate::android_audit::{AndroidAuditReport, AuditFinding, audit_dex_into};
use crate::dalvik::{DalvikInsn, decode_method};
use crate::dex::{
    CodeItem, DexCodeState, DexFile, DexMethodCode, MethodId, parse as parse_dex, parse_code_items,
};
use crate::error::Result;
use crate::jar::{ApkExtract, extract_apk};

const CODE_ITEM_HEADER_BYTES: u64 = 16;
const MAX_CONST4_REGISTER: u16 = 15;
const SITE_BYTES: usize = 8;
const OP_CONST_4: u8 = 0x12;
const OP_NOP: u8 = 0x00;
const OP_MOVE_RESULT: u8 = 0x0A;
const STRING_COMPARISONS: &[&str] = &[
    "startsWith",
    "endsWith",
    "equals",
    "equalsIgnoreCase",
    "contains",
    "matches",
    "contentEquals",
];
const FILE_PROBES: &[&str] = &["exists", "isFile", "canRead", "canExecute", "isDirectory"];
const RISK: &str = "the check's boolean result register is forced to false and the call is removed; the patched classes.dex is written beside the input, never into it, and the APK must be repacked and re-signed before it installs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexNeutralization {
    pub entry: String,
    pub bytes: Vec<u8>,
    pub audited_sites: usize,
    pub plan: NeutralizationPlan,
}

pub fn plan_apk_neutralization(apk: &[u8]) -> Result<Vec<DexNeutralization>> {
    let extract: ApkExtract = extract_apk(apk)?;
    let mut plans: Vec<DexNeutralization> = Vec::with_capacity(extract.dex_files.len());
    for (entry, bytes) in &extract.dex_files {
        let (plan, audited_sites): (NeutralizationPlan, usize) = plan_dex_neutralization(bytes)?;
        plans.push(DexNeutralization {
            entry: entry.clone(),
            bytes: bytes.clone(),
            audited_sites,
            plan,
        });
    }
    Ok(plans)
}

pub fn plan_dex_neutralization(bytes: &[u8]) -> Result<(NeutralizationPlan, usize)> {
    let dex: DexFile = parse_dex(bytes)?;
    let code = parse_code_items(&dex, bytes);
    let mut audit: AndroidAuditReport = AndroidAuditReport::default();
    audit_dex_into(&dex, bytes, &mut audit);
    let mut plan: NeutralizationPlan = NeutralizationPlan::new(bytes);
    let mut sites: usize = 0;
    for finding in &audit.findings {
        let Some(check) = check_for(finding) else {
            continue;
        };
        sites = sites.saturating_add(1);
        let method: Option<(&DexMethodCode, &CodeItem)> = code
            .methods()
            .iter()
            .find(|m: &&DexMethodCode| {
                (
                    m.class.as_str(),
                    m.method_name.as_str(),
                    m.method_descriptor.as_str(),
                ) == (
                    finding.class.as_str(),
                    finding.method.as_str(),
                    finding.descriptor.as_str(),
                )
            })
            .and_then(|m: &DexMethodCode| match m.state {
                DexCodeState::Decoded(index) => {
                    code.decoded().get(index).map(|item: &CodeItem| (m, item))
                }
                _ => None,
            });
        let Some((method, item)) = method else {
            plan.refusals
                .push(refusal(check, finding, "the method body did not decode"));
            continue;
        };
        if check == RuntimeCheck::AndroidSuExecution {
            plan.refusals.push(refusal(
                check,
                finding,
                "replacing a process launch changes behaviour beyond the check; remove the call by hand",
            ));
            continue;
        }
        let insns: Vec<DalvikInsn> = decode_method(&item.insns);
        match patch_site(bytes, &dex, method, &insns, finding, check) {
            Ok(patch) => {
                if let Err(error) = plan.push_patch(patch) {
                    plan.refusals
                        .push(refusal(check, finding, &error.to_string()));
                }
            }
            Err(reason) => plan.refusals.push(refusal(check, finding, reason)),
        }
    }
    Ok((plan, sites))
}

fn check_for(finding: &AuditFinding) -> Option<RuntimeCheck> {
    match finding.rule_id.as_str() {
        "DR-APK-DEBUGGER-CHECK" => Some(RuntimeCheck::AndroidDebuggerConnected),
        "DR-APK-EMULATOR-CHECK" => Some(RuntimeCheck::AndroidEmulatorFingerprint),
        "DR-APK-ROOT-DETECTION" => Some(RuntimeCheck::AndroidRootBinary),
        "DR-APK-ROOT-SU-COMMAND" => Some(RuntimeCheck::AndroidSuExecution),
        _ => None,
    }
}

fn refusal(check: RuntimeCheck, finding: &AuditFinding, reason: &str) -> Refusal {
    Refusal {
        check,
        anchor: Anchor {
            address: u64::from(finding.pc),
            instruction: format!("{}->{} {}", finding.class, finding.method, finding.evidence),
            pattern: String::new(),
        },
        reason: reason.to_owned(),
    }
}

fn callee<'a>(dex: &'a DexFile, insn: &DalvikInsn) -> Option<&'a MethodId> {
    if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
        return None;
    }
    insn.index
        .and_then(|index: u32| dex.method_ids.get(usize::try_from(index).ok()?))
}

fn site_position(
    dex: &DexFile,
    insns: &[DalvikInsn],
    finding: &AuditFinding,
    check: RuntimeCheck,
) -> std::result::Result<usize, &'static str> {
    let start: usize = insns
        .iter()
        .position(|insn: &DalvikInsn| insn.pc == finding.pc)
        .ok_or("the audited instruction offset is not an instruction boundary")?;
    match check {
        RuntimeCheck::AndroidDebuggerConnected => Ok(start),
        RuntimeCheck::AndroidEmulatorFingerprint => insns
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, insn): &(usize, &DalvikInsn)| {
                callee(dex, insn).is_some_and(|m: &MethodId| {
                    m.class == "Ljava/lang/String;" && STRING_COMPARISONS.contains(&m.name.as_str())
                })
            })
            .map(|(index, _): (usize, &DalvikInsn)| index)
            .ok_or("no String comparison consumes the emulator literal in this method"),
        RuntimeCheck::AndroidRootBinary => insns
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, insn): &(usize, &DalvikInsn)| {
                callee(dex, insn).is_some_and(|m: &MethodId| {
                    m.class == "Ljava/io/File;" && FILE_PROBES.contains(&m.name.as_str())
                })
            })
            .map(|(index, _): (usize, &DalvikInsn)| index)
            .ok_or("no java.io.File probe consumes the root indicator path in this method"),
        _ => Err("no patch shape is defined for this check"),
    }
}

fn patch_site(
    bytes: &[u8],
    dex: &DexFile,
    method: &DexMethodCode,
    insns: &[DalvikInsn],
    finding: &AuditFinding,
    check: RuntimeCheck,
) -> std::result::Result<Patch, &'static str> {
    let position: usize = site_position(dex, insns, finding, check)?;
    let invoke: &DalvikInsn = insns.get(position).ok_or("the call site vanished")?;
    let result: &DalvikInsn = insns
        .get(position + 1)
        .ok_or("the call is the last instruction of the method")?;
    if !matches!(invoke.op, 0x6E..=0x72 | 0x74..=0x78) || invoke.width != 3 {
        return Err("the site is not a three-unit invoke instruction");
    }
    if result.op != OP_MOVE_RESULT || result.width != 1 {
        return Err("the call's boolean result is not taken by move-result");
    }
    let Some(&destination) = result.regs.first() else {
        return Err("move-result names no register");
    };
    if destination > MAX_CONST4_REGISTER {
        return Err("the result register is beyond the const/4 range");
    }
    let file_offset: u64 = u64::from(method.code_offset)
        .checked_add(CODE_ITEM_HEADER_BYTES)
        .and_then(|insns_start: u64| insns_start.checked_add(u64::from(invoke.pc).checked_mul(2)?))
        .ok_or("the code item offset overflows")?;
    let start: usize =
        usize::try_from(file_offset).map_err(|_| "the code item offset overflows")?;
    let original: &[u8] = bytes
        .get(
            start
                ..start
                    .checked_add(SITE_BYTES)
                    .ok_or("the code item offset overflows")?,
        )
        .ok_or("the call site lies outside the dex")?;
    let callee_name: String = callee(dex, invoke)
        .map(|m: &MethodId| format!("{}->{}", m.class, m.name))
        .unwrap_or_default();
    let replacement: Vec<u8> = vec![
        OP_CONST_4,
        destination as u8,
        OP_NOP,
        OP_NOP,
        OP_NOP,
        OP_NOP,
        OP_NOP,
        OP_NOP,
    ];
    Ok(Patch {
        id: format!("{}-{file_offset:x}", check.label()),
        check,
        anchor: Anchor {
            address: file_offset,
            instruction: format!(
                "{}->{}: {} {callee_name} at pc {:#x}; move-result v{destination}",
                finding.class, finding.method, invoke.mnemonic, invoke.pc
            ),
            pattern: format!("const/4 v{destination}, #0; nop; nop; nop"),
        },
        file_offset,
        original: original.to_vec(),
        replacement,
        risk: RISK.to_owned(),
    })
}
