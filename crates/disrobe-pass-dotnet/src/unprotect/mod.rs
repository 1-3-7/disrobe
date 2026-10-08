#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod bitmono;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod body;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod closures;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod confuserex;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod deflatten;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod names;
#[cfg(not(target_arch = "wasm32"))]
pub mod neutralize;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod obfuscar;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::cil::MethodBody;
use crate::error::Result;
#[cfg(not(target_arch = "wasm32"))]
pub use neutralize::NeutralizationPlan;
#[cfg(target_arch = "wasm32")]
pub type NeutralizationPlan = ();

const SYNTHETIC_STRING_BASE: u32 = 0x70F0_0000;
const MAX_SYNTHETIC_STRINGS: u32 = 0x000F_FFFF;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Residual {
    pub layer: String,
    pub method_token: Option<u32>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerOutcome {
    pub layer: String,
    pub sites: u32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnprotectReport {
    pub protector: String,
    pub neutralised: Vec<LayerOutcome>,
    pub residuals: Vec<Residual>,
    pub fully_recovered: bool,
    pub rewritten_methods: u32,
    pub omitted_methods: u32,
    pub omitted_types: u32,
    pub plan: NeutralizationPlan,
}

#[derive(Debug, Default)]
pub struct Literals {
    units: BTreeMap<u32, Vec<u16>>,
    next: u32,
}

impl Literals {
    pub(crate) fn intern(&mut self, units: Vec<u16>) -> Option<u32> {
        if self.next >= MAX_SYNTHETIC_STRINGS {
            return None;
        }
        let token: u32 = SYNTHETIC_STRING_BASE | self.next;
        self.next = self.next.saturating_add(1);
        self.units.insert(token, units);
        Some(token)
    }

    #[must_use]
    pub fn units(&self, token: u32) -> Option<&[u16]> {
        self.units.get(&token).map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.units.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

#[derive(Debug)]
pub struct Unprotected {
    pub image: Vec<u8>,
    pub report: UnprotectReport,
    pub literals: Literals,
    pub member_renames: BTreeMap<u32, String>,
    pub type_renames: BTreeMap<u32, String>,
    pub namespace_renames: BTreeMap<String, String>,
    bodies: BTreeMap<u32, MethodBody>,
    omitted_methods: BTreeSet<u32>,
    omitted_types: BTreeSet<u32>,
}

impl Unprotected {
    #[must_use]
    pub fn rewritten(&self, method_token: u32) -> Option<&MethodBody> {
        self.bodies.get(&method_token)
    }

    #[must_use]
    pub fn omits_method(&self, method_token: u32) -> bool {
        self.omitted_methods.contains(&method_token)
    }

    #[must_use]
    pub fn omits_type(&self, type_token: u32) -> bool {
        self.omitted_types.contains(&type_token)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn unprotect(image: &[u8]) -> Result<Option<Unprotected>> {
    engine::unprotect(image)
}

#[cfg(target_arch = "wasm32")]
pub fn unprotect(_image: &[u8]) -> Result<Option<Unprotected>> {
    Ok(None)
}

#[cfg(not(target_arch = "wasm32"))]
mod engine {
    use std::collections::{BTreeMap, BTreeSet};

    use super::neutralize::{self, NeutralizationPlan};

    use super::{
        LayerOutcome, Literals, Residual, UnprotectReport, Unprotected, bitmono, confuserex,
        deflatten, names, obfuscar,
    };
    use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
    use crate::error::Result;
    use crate::metadata::{MetadataRoot, parse_metadata_root};
    use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
    use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
    use crate::peel::deflatten::predicate::PredicateOracle;
    use crate::protectors::{DetectionReport, Protector, detect_all};
    use crate::signature::TypeSig;
    use crate::tables::{MemberRefRow, MethodSpecRow, RowRef, TableId, TypeDefRow};

    const MAX_US_HEAP_FOR_SYNTHETICS: u32 = 0x00F0_0000;
    const TYPE_VISIBILITY_MASK: u32 = 0x0000_0007;
    const TYPE_PUBLIC: u32 = 0x0000_0001;
    const TYPE_NESTED_PUBLIC: u32 = 0x0000_0002;
    const MAX_REACHABILITY_STEPS: usize = 1 << 20;

    pub(crate) const LAYER_CONTROL_FLOW: &str = "control-flow flattening";
    pub(crate) const LAYER_ANTI_TAMPER: &str = "ConfuserEx anti-tamper";
    pub(crate) const LAYER_HEADERS: &str = "BitMono AntiILdasm/BitDotNet header corruption";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Family {
        ConfuserEx,
        BitMono,
        Obfuscar,
    }

    fn family_of(report: &DetectionReport) -> Option<(Protector, Family)> {
        let primary: Protector = report.primary?;
        let family: Family = match primary {
            Protector::ConfuserEx | Protector::ConfuserEx2 => Family::ConfuserEx,
            Protector::BitMono => Family::BitMono,
            Protector::Obfuscar => Family::Obfuscar,
            _ => return None,
        };
        Some((primary, family))
    }

    const CLR_DIRECTORY_INDEX: usize = 14;
    const CLR_HEADER_SIZE: u32 = 72;
    const NT_SIGNATURE: u32 = 0x0000_4550;
    const PE32_MAGIC: u16 = 0x10B;

    fn write_u32(image: &mut [u8], offset: usize, value: u32) -> bool {
        image
            .get_mut(offset..offset + 4)
            .is_some_and(|slot: &mut [u8]| {
                slot.copy_from_slice(&value.to_le_bytes());
                true
            })
    }

    fn read_u32(image: &[u8], offset: usize) -> Option<u32> {
        let bytes: &[u8] = image.get(offset..offset + 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn repair_headers(
        image: &mut [u8],
        root: &MetadataRoot,
        input: &[u8],
        plan: &mut NeutralizationPlan,
    ) -> u32 {
        let mut repaired: u32 = 0;
        let risk: &str = "the header words are restored to the values every loader derives from the image; no code changes";
        let mut restore = |image: &mut [u8], offset: usize, value: u32, what: &str| -> bool {
            if !write_u32(image, offset, value) {
                return false;
            }
            if let Some(patch) = neutralize::raw_patch(
                input,
                neutralize::Technique::HeaderCorruption,
                what,
                offset,
                value.to_le_bytes().to_vec(),
                format!("{what} restored to {value:#x}"),
                risk,
            ) {
                plan.push(patch);
            }
            true
        };
        let Some(lfanew): Option<usize> =
            read_u32(image, 0x3C).and_then(|v: u32| usize::try_from(v).ok())
        else {
            return 0;
        };
        if read_u32(image, lfanew).is_some_and(|sig: u32| sig != NT_SIGNATURE)
            && restore(image, lfanew, NT_SIGNATURE, "nt-signature")
        {
            repaired += 1;
        }
        let optional: usize = lfanew + 24;
        let magic: u16 = image
            .get(optional..optional + 2)
            .map_or(0, |b: &[u8]| u16::from_le_bytes([b[0], b[1]]));
        let directories: usize = optional + if magic == PE32_MAGIC { 96 } else { 112 };
        let clr_dir: usize = directories + CLR_DIRECTORY_INDEX * 8;
        let Some(clr_rva): Option<u32> = read_u32(image, clr_dir) else {
            return repaired;
        };
        if clr_rva != 0
            && read_u32(image, clr_dir + 4) == Some(0)
            && restore(image, clr_dir + 4, CLR_HEADER_SIZE, "clr-directory-size")
        {
            repaired += 1;
        }
        let Ok(pe): Result<PeImage> = parse(image) else {
            return repaired;
        };
        let Some(clr_offset): Option<usize> = pe.rva_to_offset(clr_rva) else {
            return repaired;
        };
        if read_u32(image, clr_offset) == Some(0)
            && restore(image, clr_offset, CLR_HEADER_SIZE, "clr-header-size")
        {
            repaired += 1;
        }
        let extent: u32 = root
            .streams
            .values()
            .map(|s| s.offset.saturating_add(s.size))
            .max()
            .unwrap_or(0);
        if read_u32(image, clr_offset + 12) == Some(0)
            && extent != 0
            && restore(image, clr_offset + 12, extent, "metadata-size")
        {
            repaired += 1;
        }
        repaired
    }

    const MAX_INITIALIZER_DEPTH: usize = 4;
    const MAX_INITIALIZER_VISITS: usize = 512;

    fn initializer_technique(
        image: &[u8],
        pe: &PeImage,
        resolver: &Resolver,
        module: &TypeModel,
        root: u32,
    ) -> Option<(neutralize::Technique, String)> {
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        let mut work: Vec<(u32, usize)> = vec![(root, 0)];
        let mut evidence: BTreeSet<String> = BTreeSet::new();
        while let Some((token, depth)) = work.pop() {
            if visited.len() >= MAX_INITIALIZER_VISITS || !visited.insert(token) {
                continue;
            }
            let Some(m): Option<&MethodModel> = module
                .methods
                .iter()
                .find(|m: &&MethodModel| m.token == token)
            else {
                continue;
            };
            if m.flags & 0x2000 != 0 {
                evidence.insert(format!("pinvoke {}", m.name));
                continue;
            }
            let Some(body): Option<MethodBody> = confuserex::method_body(image, pe, m) else {
                continue;
            };
            for ins in &body.instructions {
                let OperandValue::Token(callee) = ins.operand else {
                    continue;
                };
                if !matches!(ins.name.as_str(), "call" | "callvirt" | "ldftn" | "newobj") {
                    continue;
                }
                if callee >> 24 == 0x06 {
                    if depth < MAX_INITIALIZER_DEPTH {
                        work.push((callee, depth + 1));
                    }
                    continue;
                }
                let name: String = resolver.resolve_token(callee);
                if name.contains("Debugger::get_IsAttached")
                    || name.contains("Debugger::IsLogging")
                    || name.contains("Environment::FailFast")
                    || name.contains("Debugger::IsAttached")
                    || name.contains("VirtualProtect")
                    || name.contains("Marshal::GetHINSTANCE")
                    || name.contains("ZeroMemory")
                {
                    evidence.insert(name);
                }
            }
        }
        if evidence.is_empty() {
            return None;
        }
        let dumps: bool = evidence.iter().any(|e: &String| {
            e.contains("VirtualProtect") || e.contains("GetHINSTANCE") || e.contains("ZeroMemory")
        });
        let debugs: bool = evidence
            .iter()
            .any(|e: &String| e.contains("Debugger") || e.contains("FailFast"));
        let technique: neutralize::Technique = if debugs {
            neutralize::Technique::AntiDebug
        } else if dumps {
            neutralize::Technique::AntiDump
        } else {
            return None;
        };
        let detail: String = evidence.into_iter().collect::<Vec<String>>().join(", ");
        Some((technique, detail))
    }

    const MAX_THREAD_START_SPAN: usize = 16;

    fn stack_delta(ins: &Instruction, resolver: &Resolver) -> Option<i32> {
        let name: &str = ins.name.as_str();
        if name == "dup"
            || name == "ldnull"
            || name == "ldftn"
            || name.starts_with("ldc.")
            || name.starts_with("ldsfld")
            || name.starts_with("ldloc")
            || name.starts_with("ldarg")
        {
            return Some(1);
        }
        if name.starts_with("stloc") || name.starts_with("stsfld") || name == "pop" {
            return Some(-1);
        }
        if !matches!(name, "call" | "callvirt" | "newobj") {
            return None;
        }
        let OperandValue::Token(token) = ins.operand else {
            return None;
        };
        let signature: crate::signature::MethodSig = resolver.callee_signature(token)?;
        let params: i32 = i32::try_from(signature.params.len()).ok()?;
        if name == "newobj" {
            return Some(1 - params);
        }
        let this: i32 = i32::from(signature.has_this);
        let pushes: i32 = i32::from(!matches!(
            signature.return_type,
            crate::signature::TypeSigOrVoid::Void
        ));
        Some(pushes - params - this)
    }

    fn thread_start_span(
        body: &MethodBody,
        ldftn: usize,
        resolver: &Resolver,
    ) -> Option<(usize, usize)> {
        let instrs: &[Instruction] = &body.instructions;
        let end: usize = instrs
            .iter()
            .enumerate()
            .skip(ldftn)
            .take(MAX_THREAD_START_SPAN)
            .find(|(_, i): &(usize, &Instruction)| {
                matches!(i.name.as_str(), "call" | "callvirt")
                    && matches!(i.operand, OperandValue::Token(t)
                        if resolver.resolve_token(t).starts_with("System.Threading.Thread::Start"))
            })
            .map(|(index, _): (usize, &Instruction)| index + 1)?;
        for start in (ldftn.saturating_sub(2)..=ldftn).rev() {
            let mut depth: i32 = 0;
            let mut balanced: bool = true;
            for ins in &instrs[start..end] {
                let Some(delta) = stack_delta(ins, resolver) else {
                    balanced = false;
                    break;
                };
                depth += delta;
                if depth < 0 {
                    balanced = false;
                    break;
                }
            }
            if balanced && depth == 0 {
                return Some((start, end));
            }
        }
        None
    }

    fn confuserex_initializer_patches(
        site: &neutralize::IlSite<'_>,
        image: &[u8],
        pe: &PeImage,
        resolver: &Resolver,
        model: &AssemblyModel,
        anti_tamper_initializer: Option<u32>,
        plan: &mut NeutralizationPlan,
    ) {
        let Some(module): Option<&TypeModel> = confuserex::module_type(model) else {
            return;
        };
        let Some(cctor): Option<&MethodModel> = module
            .methods
            .iter()
            .find(|m: &&MethodModel| m.name == ".cctor")
        else {
            return;
        };
        let Some(body): Option<MethodBody> = confuserex::method_body(image, pe, cctor) else {
            return;
        };
        for (index, ins) in body.instructions.iter().enumerate() {
            if ins.name == "ldftn"
                && let OperandValue::Token(worker) = ins.operand
                && let Some((technique, detail)) =
                    initializer_technique(image, pe, resolver, module, worker)
                && let Some((start, end)) = thread_start_span(&body, index, resolver)
                && let Some(patch) = site.nop_patch(
                    technique,
                    neutralize::MethodRef::new(cctor.token, cctor.rva),
                    &body,
                    (start, end),
                    format!(
                        "module initializer starts a thread on {worker:#010x} ({} instructions): {detail}",
                        end - start
                    ),
                    "the watchdog thread is never created; the removed span only builds and starts it",
                )
            {
                plan.push(patch);
                continue;
            }
            if ins.name != "call" {
                continue;
            }
            let OperandValue::Token(callee) = ins.operand else {
                continue;
            };
            let classified: Option<(neutralize::Technique, String)> = if Some(callee)
                == anti_tamper_initializer
            {
                Some((
                    neutralize::Technique::AntiTamper,
                    format!(
                        "anti-tamper initializer {callee:#010x} called from the module initializer"
                    ),
                ))
            } else {
                initializer_technique(image, pe, resolver, module, callee)
            };
            let Some((technique, detail)) = classified else {
                continue;
            };
            let risk: &str = match technique {
                neutralize::Technique::AntiTamper => {
                    "must be applied together with the section patch, otherwise the loader runs encrypted bodies"
                }
                neutralize::Technique::AntiDebug => {
                    "the watchdog thread that calls Environment.FailFast under a debugger is never started; nothing else runs in the removed call"
                }
                _ => {
                    "the memory-protection calls that hide the image from dumpers are skipped; nothing else runs in the removed call"
                }
            };
            if let Some(patch) = site.nop_patch(
                technique,
                neutralize::MethodRef::new(cctor.token, cctor.rva),
                &body,
                (index, index + 1),
                format!("module initializer call to {callee:#010x}: {detail}"),
                risk,
            ) {
                plan.push(patch);
            }
        }
    }

    struct Layers {
        confuserex: Option<confuserex::ConfuserExLayer>,
        bitmono: Option<bitmono::BitMonoLayer>,
        obfuscar: Option<obfuscar::ObfuscarLayer>,
        oracle: Option<PredicateOracle>,
        flattened: u32,
    }

    pub(super) fn unprotect(image: &[u8]) -> Result<Option<Unprotected>> {
        let detection: DetectionReport = detect_all(image);
        let Some((protector, family)): Option<(Protector, Family)> = family_of(&detection) else {
            return Ok(None);
        };
        let input: &[u8] = image;
        let mut image: Vec<u8> = image.to_vec();
        let mut neutralised: Vec<LayerOutcome> = Vec::new();
        let mut residuals: Vec<Residual> = Vec::new();
        let mut plan: NeutralizationPlan = NeutralizationPlan::default();
        let mut anti_tamper_initializer: Option<u32> = None;
        if family == Family::ConfuserEx {
            match crate::peel::confuserex_anti_tamper::decrypt_anti_tamper(&image)? {
                crate::peel::confuserex_anti_tamper::AntiTamperOutcome::Absent => {}
                crate::peel::confuserex_anti_tamper::AntiTamperOutcome::Decrypted {
                    recovery,
                    image: decrypted,
                } => {
                    neutralised.push(LayerOutcome {
                        layer: LAYER_ANTI_TAMPER.to_owned(),
                        sites: recovery.methods_in_section,
                        detail: format!(
                            "section {:?} at {:#x} decrypted with the key the initializer {:#x} derives from the image hash; only the first 64 bytes depend on that key, the rest of the stream self-synchronises from the ciphertext ({} bytes changed)",
                            recovery.section_name,
                            recovery.section_rva,
                            recovery.initializer_token,
                            recovery.bytes_changed
                        ),
                    });
                    anti_tamper_initializer = Some(recovery.initializer_token);
                    if let Ok(pe) = parse(input)
                        && let Some(raw) = pe.rva_to_offset(recovery.section_rva)
                        && let Some(size) = usize::try_from(recovery.section_size).ok()
                        && let Some(replacement) = decrypted.get(raw..raw.saturating_add(size))
                        && let Some(patch) = neutralize::raw_patch(
                            input,
                            neutralize::Technique::AntiTamper,
                            "section",
                            raw,
                            replacement.to_vec(),
                            format!(
                                "section {:?} at {:#x} rewritten with the bodies the initializer {:#x} decrypts at load",
                                recovery.section_name,
                                recovery.section_rva,
                                recovery.initializer_token
                            ),
                            "the initializer call is removed with it; applied alone, the runtime decryptor would re-encrypt the plaintext",
                        )
                    {
                        plan.push(patch);
                    }
                    image = decrypted;
                }
                crate::peel::confuserex_anti_tamper::AntiTamperOutcome::Refused {
                    initializer_token,
                    reason,
                } => residuals.push(Residual {
                    layer: LAYER_ANTI_TAMPER.to_owned(),
                    method_token: Some(initializer_token),
                    reason,
                }),
            }
        }
        let mut repaired_type_renames: BTreeMap<u32, String> = BTreeMap::new();
        let mut repaired_member_renames: BTreeMap<u32, String> = BTreeMap::new();
        {
            let pe: PeImage = parse(&image)?;
            let clr: ClrHeader = parse_clr_header(&image, &pe)?;
            let root: MetadataRoot = parse_metadata_root(&image, &pe, &clr)?;
            if family == Family::BitMono {
                let repaired: u32 = repair_headers(&mut image, &root, input, &mut plan);
                if repaired > 0 {
                    neutralised.push(LayerOutcome {
                        layer: LAYER_HEADERS.to_owned(),
                        sites: repaired,
                        detail: "NT signature, CLR directory size and metadata size restored"
                            .to_owned(),
                    });
                }
            }
            let pe: PeImage = parse(&image)?;
            let clr: ClrHeader = parse_clr_header(&image, &pe)?;
            let root: MetadataRoot = parse_metadata_root(&image, &pe, &clr)?;
            let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root)?;
            if let Some(repair) =
                names::repair_identifiers(&mut image, &pe, &clr, &root, resolver.tables())
            {
                let deferred: usize = repair.type_renames.len() + repair.member_renames.len();
                if repair.rewritten > 0 || deferred > 0 {
                    neutralised.push(LayerOutcome {
                        layer: names::LAYER_NAMES.to_owned(),
                        sites: repair
                            .rewritten
                            .saturating_add(u32::try_from(deferred).unwrap_or(u32::MAX)),
                        detail: format!(
                            "characters outside the identifier grammar replaced by underscores: {} names in place, {} names sharing heap bytes renamed in the resolver",
                            repair.rewritten, deferred
                        ),
                    });
                }
                repaired_type_renames = repair.type_renames;
                repaired_member_renames = repair.member_renames;
            }
        }
        let pe: PeImage = parse(&image)?;
        let clr: ClrHeader = parse_clr_header(&image, &pe)?;
        let root: MetadataRoot = parse_metadata_root(&image, &pe, &clr)?;
        let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root)?;
        let model: AssemblyModel = resolver.model();
        let us_heap_size: u32 = root.streams.get("#US").map_or(0, |s| s.size);

        let mut literals: Literals = Literals::default();
        let mut bodies: BTreeMap<u32, MethodBody> = BTreeMap::new();
        let mut runtime_methods: BTreeSet<u32> = BTreeSet::new();
        let mut runtime_types: BTreeSet<u32> = BTreeSet::new();
        let synthetics_allowed: bool = us_heap_size <= MAX_US_HEAP_FOR_SYNTHETICS;
        if !synthetics_allowed {
            residuals.push(Residual {
                layer: "synthetic string table".to_owned(),
                method_token: None,
                reason: format!(
                    "the #US heap is {us_heap_size} bytes, beyond the {MAX_US_HEAP_FOR_SYNTHETICS}-byte range reserved for inlined literals"
                ),
            });
        }

        let mut layers: Layers = Layers {
            confuserex: None,
            bitmono: None,
            obfuscar: None,
            oracle: None,
            flattened: 0,
        };
        match family {
            Family::ConfuserEx => {
                let layer: confuserex::ConfuserExLayer =
                    confuserex::ConfuserExLayer::build(&image, &pe, &resolver, &model);
                runtime_methods.extend(layer.runtime_methods.iter().copied());
                runtime_methods.extend(layer.proxies.keys().copied());
                if let Some(module) = confuserex::module_type(&model) {
                    runtime_types.insert(module.token);
                }
                layers.confuserex = Some(layer);
                layers.oracle = Some(PredicateOracle::build(&image, &pe, &model));
            }
            Family::BitMono => {
                let layer: bitmono::BitMonoLayer =
                    bitmono::BitMonoLayer::build(&image, &pe, &resolver, &model, &mut residuals);
                runtime_methods.extend(layer.runtime_methods.iter().copied());
                runtime_types.extend(layer.runtime_types.iter().copied());
                layers.bitmono = Some(layer);
                layers.oracle = Some(PredicateOracle::build(&image, &pe, &model));
            }
            Family::Obfuscar => {
                let layer: obfuscar::ObfuscarLayer = obfuscar::ObfuscarLayer::build(
                    &image,
                    &model,
                    &resolver.tables().nested_classes,
                    &mut residuals,
                );
                runtime_methods.extend(layer.runtime_methods.iter().copied());
                runtime_types.extend(layer.runtime_types.iter().copied());
                layers.obfuscar = Some(layer);
            }
        }

        for ty in &model.types {
            for m in &ty.methods {
                if runtime_methods.contains(&m.token) {
                    continue;
                }
                let Some(mut body): Option<MethodBody> = parse_body(&image, &pe, m) else {
                    continue;
                };
                let mut changed: bool = false;
                if synthetics_allowed {
                    if let Some(layer) = layers.confuserex.as_mut()
                        && layer.present()
                    {
                        changed |= layer.rewrite(
                            m.token,
                            &mut body,
                            &resolver,
                            &mut literals,
                            &mut residuals,
                        );
                    }
                    if let Some(layer) = layers.bitmono.as_mut() {
                        changed |= layer.rewrite(
                            m.token,
                            &mut body,
                            &resolver,
                            &mut literals,
                            &mut residuals,
                        );
                    }
                    if let Some(layer) = layers.obfuscar.as_mut()
                        && layer.present()
                    {
                        changed |= layer.rewrite(m.token, &mut body, &mut literals, &mut residuals);
                    }
                }
                if let Some(oracle) = layers.oracle.as_ref() {
                    match deflatten::deflatten(&body, oracle) {
                        deflatten::DeflattenOutcome::NotFlattened => {}
                        deflatten::DeflattenOutcome::Rebuilt(rebuilt) => {
                            layers.flattened = layers.flattened.saturating_add(1);
                            body = rebuilt;
                            changed = true;
                        }
                        deflatten::DeflattenOutcome::Residual(reason) => {
                            residuals.push(Residual {
                                layer: LAYER_CONTROL_FLOW.to_owned(),
                                method_token: Some(m.token),
                                reason,
                            });
                        }
                    }
                }
                if changed {
                    bodies.insert(m.token, body);
                }
            }
        }

        if let Some(layer) = &layers.confuserex {
            if let Some(reason) = layer.ledger.inconsistency() {
                residuals.push(Residual {
                    layer: confuserex::LAYER_CONSTANTS.to_owned(),
                    method_token: None,
                    reason,
                });
            }
            if layer.constant_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: confuserex::LAYER_CONSTANTS.to_owned(),
                    sites: layer.constant_sites,
                    detail: format!(
                        "{} decoder methods; {}{}",
                        layer.decoders.len(),
                        layer.pool_detail,
                        layer
                            .pool
                            .as_ref()
                            .filter(|p| p.seed != 0)
                            .map_or(String::new(), |p| format!(" {:#010x}", p.seed))
                    ),
                });
            }
            if layer.proxy_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: confuserex::LAYER_REF_PROXY.to_owned(),
                    sites: layer.proxy_sites,
                    detail: format!("{} static proxy methods inlined", layer.proxies.len()),
                });
            }
            if layer.junk_branches > 0 {
                neutralised.push(LayerOutcome {
                    layer: confuserex::LAYER_JUNK.to_owned(),
                    sites: layer.junk_branches,
                    detail: "branches to the next instruction removed".to_owned(),
                });
            }
        }
        if let Some(layer) = &layers.bitmono {
            if layer.string_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: bitmono::LAYER_STRINGS.to_owned(),
                    sites: layer.string_sites,
                    detail: "AES-CBC/PBKDF2 string call sites decrypted from the embedded data, salt and password fields".to_owned(),
                });
            }
            if layer.hook_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: bitmono::LAYER_HOOK.to_owned(),
                    sites: layer.hook_sites,
                    detail: layer.hook_detail.clone(),
                });
            }
            if layer.calli_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: bitmono::LAYER_CALLI.to_owned(),
                    sites: layer.calli_sites,
                    detail: "runtime-resolved function pointers folded back to direct calls"
                        .to_owned(),
                });
            }
            if layer.anti_debug_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: bitmono::LAYER_ANTI_DEBUG.to_owned(),
                    sites: layer.anti_debug_sites,
                    detail: "UtcNow timing checks that divide by zero after five seconds removed"
                        .to_owned(),
                });
            }
            if layer.junk_sites > 0 {
                neutralised.push(LayerOutcome {
                    layer: bitmono::LAYER_JUNK.to_owned(),
                    sites: layer.junk_sites,
                    detail: "unreachable instructions behind the leading branch removed".to_owned(),
                });
            }
        }
        if let Some(layer) = &layers.obfuscar
            && layer.string_sites > 0
        {
            neutralised.push(LayerOutcome {
                layer: obfuscar::LAYER_HIDE_STRINGS.to_owned(),
                sites: layer.string_sites,
                detail: format!(
                    "{} carrier types; accessor calls replaced by the literals read from the FieldRVA carrier",
                    layer.carrier_count
                ),
            });
        }
        if layers.flattened > 0 {
            neutralised.push(LayerOutcome {
                layer: LAYER_CONTROL_FLOW.to_owned(),
                sites: layers.flattened,
                detail: "switch dispatchers rebuilt into direct control flow".to_owned(),
            });
        }

        {
            let site: neutralize::IlSite<'_> = neutralize::IlSite { input, pe: &pe };
            if let Some(layer) = layers.bitmono.as_ref() {
                layer.plan(&site, &image, &pe, &resolver, &model, &mut plan);
            }
            if layers.confuserex.is_some() {
                confuserex_initializer_patches(
                    &site,
                    &image,
                    &pe,
                    &resolver,
                    &model,
                    anti_tamper_initializer,
                    &mut plan,
                );
            }
        }
        let reach: Reachability = Reachability::compute(
            &image,
            &pe,
            &clr,
            &resolver,
            &model,
            &bodies,
            &runtime_methods,
            &runtime_types,
        );
        let mut type_renames: BTreeMap<u32, String> = repaired_type_renames;
        type_renames.extend(namespace_shadow_renames(&model));
        let mut member_renames: BTreeMap<u32, String> = repaired_member_renames;
        member_renames.extend(enclosing_name_renames(&model, &type_renames));
        let namespace_renames: BTreeMap<String, String> = colliding_namespace_renames(&model);
        let rename_count: usize =
            member_renames.len() + type_renames.len() + namespace_renames.len();
        if rename_count > 0 {
            neutralised.push(LayerOutcome {
                layer: names::LAYER_SHADOWED_MEMBERS.to_owned(),
                sites: u32::try_from(rename_count).unwrap_or(u32::MAX),
                detail: "members named like their enclosing type, fields named like a method, types named like a namespace segment, and namespaces named like a member get a suffix so C# name lookup matches CIL"
                    .to_owned(),
            });
        }
        let closures: super::closures::ClosureRenames = super::closures::closure_renames(
            &image,
            &pe,
            &resolver,
            &model,
            &bodies,
            &member_renames,
        );
        if closures.len() > 0 {
            neutralised.push(LayerOutcome {
                layer: super::closures::LAYER_CLOSURES.to_owned(),
                sites: u32::try_from(closures.len()).unwrap_or(u32::MAX),
                detail: "closure types, lambda bodies, cached delegates and local-function helpers carrying CompilerGeneratedAttribute get their C# compiler names back so closure lowering applies"
                    .to_owned(),
            });
            type_renames.extend(closures.types);
            member_renames.extend(closures.members);
        }
        let rewritten_methods: u32 = u32::try_from(bodies.len()).unwrap_or(u32::MAX);
        let fully_recovered: bool = residuals.is_empty();
        let report: UnprotectReport = UnprotectReport {
            protector: protector.label().to_owned(),
            neutralised,
            residuals,
            fully_recovered,
            rewritten_methods,
            omitted_methods: u32::try_from(reach.omitted_methods.len()).unwrap_or(u32::MAX),
            omitted_types: u32::try_from(reach.omitted_types.len()).unwrap_or(u32::MAX),
            plan,
        };
        Ok(Some(Unprotected {
            image,
            report,
            literals,
            member_renames,
            type_renames,
            namespace_renames,
            bodies,
            omitted_methods: reach.omitted_methods,
            omitted_types: reach.omitted_types,
        }))
    }

    fn enclosing_name_renames(
        model: &AssemblyModel,
        type_renames: &BTreeMap<u32, String>,
    ) -> BTreeMap<u32, String> {
        const SPECIAL_NAME: u16 = 0x0800;
        let mut renames: BTreeMap<u32, String> = BTreeMap::new();
        for ty in &model.types {
            let effective: &str = type_renames
                .get(&ty.token)
                .map_or(ty.name.as_str(), String::as_str);
            let simple: String = effective.split('`').next().unwrap_or(effective).to_owned();
            let mut taken: BTreeSet<String> = ty
                .methods
                .iter()
                .map(|m: &MethodModel| m.name.clone())
                .chain(ty.fields.iter().map(|f| f.name.clone()))
                .collect();
            taken.insert(simple.clone());
            let mut fresh = |base: &str| -> String {
                let mut candidate: String = format!("{base}_");
                while taken.contains(&candidate) {
                    candidate.push('_');
                }
                taken.insert(candidate.clone());
                candidate
            };
            let mut method_names: BTreeSet<String> = BTreeSet::new();
            let mut property_names: BTreeSet<String> = BTreeSet::new();
            for m in &ty.methods {
                if m.name.starts_with('.') {
                    continue;
                }
                let accessor: Option<&str> = (m.flags & SPECIAL_NAME != 0)
                    .then(|| {
                        m.name
                            .strip_prefix("get_")
                            .or_else(|| m.name.strip_prefix("set_"))
                    })
                    .flatten();
                match accessor {
                    Some(property) => {
                        property_names.insert(property.to_owned());
                    }
                    None => {
                        method_names.insert(m.name.clone());
                    }
                }
            }
            let mut renamed_methods: BTreeMap<String, String> = BTreeMap::new();
            for name in &method_names {
                if *name == simple {
                    renamed_methods.insert(name.clone(), fresh(name));
                }
            }
            let mut renamed_properties: BTreeMap<String, String> = BTreeMap::new();
            for name in &property_names {
                if *name == simple || method_names.contains(name) {
                    renamed_properties.insert(name.clone(), fresh(name));
                }
            }
            for m in &ty.methods {
                if let Some(new_name) = renamed_methods.get(&m.name) {
                    renames.insert(m.token, new_name.clone());
                    continue;
                }
                for prefix in ["get_", "set_"] {
                    if m.flags & SPECIAL_NAME != 0
                        && let Some(property) = m.name.strip_prefix(prefix)
                        && let Some(new_name) = renamed_properties.get(property)
                    {
                        renames.insert(m.token, format!("{prefix}{new_name}"));
                    }
                }
            }
            for f in &ty.fields {
                if f.name == simple
                    || method_names.contains(&f.name)
                    || property_names.contains(&f.name)
                {
                    let new_name: String = fresh(&f.name);
                    renames.insert(f.token, new_name);
                }
            }
        }
        renames
    }

    fn colliding_namespace_renames(model: &AssemblyModel) -> BTreeMap<String, String> {
        let mut member_names: BTreeSet<String> = BTreeSet::new();
        for ty in &model.types {
            member_names.insert(ty.name.split('`').next().unwrap_or(&ty.name).to_owned());
            for m in &ty.methods {
                let plain: &str = m
                    .name
                    .strip_prefix("get_")
                    .or_else(|| m.name.strip_prefix("set_"))
                    .unwrap_or(&m.name);
                member_names.insert(plain.to_owned());
            }
            for f in &ty.fields {
                member_names.insert(f.name.clone());
            }
        }
        let mut renames: BTreeMap<String, String> = BTreeMap::new();
        for ty in &model.types {
            if ty.namespace.is_empty() || renames.contains_key(&ty.namespace) {
                continue;
            }
            let renamed: Vec<String> = ty
                .namespace
                .split('.')
                .map(|segment: &str| {
                    if member_names.contains(segment) {
                        format!("{segment}_ns")
                    } else {
                        segment.to_owned()
                    }
                })
                .collect();
            let joined: String = renamed.join(".");
            if joined != ty.namespace {
                renames.insert(ty.namespace.clone(), joined);
            }
        }
        renames
    }

    fn namespace_shadow_renames(model: &AssemblyModel) -> BTreeMap<u32, String> {
        let segments: BTreeSet<&str> = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.namespace.split('.'))
            .filter(|s: &&str| !s.is_empty())
            .collect();
        let taken: BTreeSet<String> = model
            .types
            .iter()
            .map(|t: &TypeModel| t.full_name.clone())
            .collect();
        let mut renames: BTreeMap<u32, String> = BTreeMap::new();
        for ty in &model.types {
            let simple: &str = ty.name.split('`').next().unwrap_or(&ty.name);
            if !segments.contains(simple) {
                continue;
            }
            let mut candidate: String = format!("{simple}_");
            while taken.contains(&format!("{}.{candidate}", ty.namespace)) {
                candidate.push('_');
            }
            if let Some(arity) = ty.name.find('`') {
                candidate.push_str(&ty.name[arity..]);
            }
            renames.insert(ty.token, candidate);
        }
        renames
    }

    fn parse_body(image: &[u8], pe: &PeImage, m: &MethodModel) -> Option<MethodBody> {
        if m.rva == 0 {
            return None;
        }
        let off: usize = pe.rva_to_offset(m.rva)?;
        parse_method_body(image.get(off..)?).ok()
    }

    struct Reachability {
        omitted_methods: BTreeSet<u32>,
        omitted_types: BTreeSet<u32>,
    }

    impl Reachability {
        #[allow(clippy::too_many_arguments)]
        fn compute(
            image: &[u8],
            pe: &PeImage,
            clr: &ClrHeader,
            resolver: &Resolver,
            model: &AssemblyModel,
            bodies: &BTreeMap<u32, MethodBody>,
            runtime_methods: &BTreeSet<u32>,
            runtime_types: &BTreeSet<u32>,
        ) -> Self {
            let mut owner_of_method: BTreeMap<u32, u32> = BTreeMap::new();
            let mut owner_of_field: BTreeMap<u32, u32> = BTreeMap::new();
            for ty in &model.types {
                for m in &ty.methods {
                    owner_of_method.insert(m.token, ty.token);
                }
                for f in &ty.fields {
                    owner_of_field.insert(f.token, ty.token);
                }
            }
            let enclosing: BTreeMap<u32, u32> = resolver
                .tables()
                .nested_classes
                .iter()
                .map(|n| {
                    (
                        0x0200_0000 | n.nested_class,
                        0x0200_0000 | n.enclosing_class,
                    )
                })
                .collect();
            let is_effectively_public = |token: u32| -> bool {
                let mut cursor: u32 = token;
                let mut guard: usize = 0;
                loop {
                    guard += 1;
                    if guard > 64 {
                        return false;
                    }
                    let Some(ty): Option<&TypeModel> =
                        model.types.iter().find(|t: &&TypeModel| t.token == cursor)
                    else {
                        return false;
                    };
                    match ty.flags & TYPE_VISIBILITY_MASK {
                        TYPE_PUBLIC => return true,
                        TYPE_NESTED_PUBLIC => match enclosing.get(&cursor) {
                            Some(outer) => cursor = *outer,
                            None => return false,
                        },
                        _ => return false,
                    }
                }
            };
            let entry_point: Option<u32> = (clr.entry_point_token_or_rva >> 24 == 0x06)
                .then_some(clr.entry_point_token_or_rva);
            let mut kept_types: BTreeSet<u32> = BTreeSet::new();
            let mut work: Vec<u32> = Vec::new();
            for ty in &model.types {
                if runtime_types.contains(&ty.token) {
                    continue;
                }
                let rooted: bool = is_effectively_public(ty.token)
                    || entry_point
                        .is_some_and(|ep: u32| owner_of_method.get(&ep) == Some(&ty.token));
                if rooted {
                    work.push(ty.token);
                }
            }
            let type_rows: &[TypeDefRow] = &resolver.tables().type_defs;
            let mut steps: usize = 0;
            while let Some(type_token) = work.pop() {
                steps += 1;
                if steps > MAX_REACHABILITY_STEPS {
                    break;
                }
                if runtime_types.contains(&type_token) || !kept_types.insert(type_token) {
                    continue;
                }
                let Some(ty): Option<&TypeModel> = model
                    .types
                    .iter()
                    .find(|t: &&TypeModel| t.token == type_token)
                else {
                    continue;
                };
                if let Some(outer) = enclosing.get(&type_token) {
                    work.push(*outer);
                }
                let rid: usize = usize::try_from(type_token & 0x00FF_FFFF)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1);
                if let Some(row) = type_rows.get(rid)
                    && let Some(base) = row.extends
                {
                    push_row_ref(resolver, base, &mut work);
                }
                for implemented in &resolver.tables().interface_impls {
                    if implemented.class_type == type_token & 0x00FF_FFFF
                        && let Some(interface) = implemented.interface
                    {
                        push_row_ref(resolver, interface, &mut work);
                    }
                }
                for f in &ty.fields {
                    let mut tokens: Vec<u32> = Vec::new();
                    f.field_type.collect_tokens(&mut tokens);
                    for t in tokens {
                        push_token(resolver, t, &owner_of_method, &owner_of_field, &mut work);
                    }
                }
                for m in &ty.methods {
                    if runtime_methods.contains(&m.token) {
                        continue;
                    }
                    let mut tokens: Vec<u32> = Vec::new();
                    for p in &m.signature.params {
                        p.collect_tokens(&mut tokens);
                    }
                    if let crate::signature::TypeSigOrVoid::Type(ret) = &m.signature.return_type {
                        ret.collect_tokens(&mut tokens);
                    }
                    for t in tokens {
                        push_token(resolver, t, &owner_of_method, &owner_of_field, &mut work);
                    }
                    let owned: Option<MethodBody> = if bodies.contains_key(&m.token) {
                        None
                    } else {
                        parse_body(image, pe, m)
                    };
                    let body: Option<&MethodBody> = bodies.get(&m.token).or(owned.as_ref());
                    let Some(body): Option<&MethodBody> = body else {
                        continue;
                    };
                    for ins in &body.instructions {
                        if let OperandValue::Token(t) = ins.operand {
                            push_token(resolver, t, &owner_of_method, &owner_of_field, &mut work);
                        }
                    }
                    if let Some(locals) = resolver.local_type_sigs(body.local_var_sig_tok) {
                        let mut tokens: Vec<u32> = Vec::new();
                        for local in &locals {
                            local.collect_tokens(&mut tokens);
                        }
                        for t in tokens {
                            push_token(resolver, t, &owner_of_method, &owner_of_field, &mut work);
                        }
                    }
                }
            }
            let mut omitted_types: BTreeSet<u32> = BTreeSet::new();
            let mut omitted_methods: BTreeSet<u32> = BTreeSet::new();
            for ty in &model.types {
                if !kept_types.contains(&ty.token) {
                    omitted_types.insert(ty.token);
                    for m in &ty.methods {
                        omitted_methods.insert(m.token);
                    }
                    continue;
                }
                for m in &ty.methods {
                    if runtime_methods.contains(&m.token) {
                        omitted_methods.insert(m.token);
                    }
                }
            }
            Self {
                omitted_methods,
                omitted_types,
            }
        }
    }

    fn push_row_ref(resolver: &Resolver, row: RowRef, work: &mut Vec<u32>) {
        match row.table {
            TableId::TypeDef => work.push(0x0200_0000 | row.row),
            TableId::TypeSpec => {
                if let Some(sig) = resolver.type_spec_sig(row.row) {
                    let mut tokens: Vec<u32> = Vec::new();
                    sig.collect_tokens(&mut tokens);
                    for t in tokens {
                        if t >> 24 == 0x02 {
                            work.push(t);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn push_token(
        resolver: &Resolver,
        token: u32,
        owner_of_method: &BTreeMap<u32, u32>,
        owner_of_field: &BTreeMap<u32, u32>,
        work: &mut Vec<u32>,
    ) {
        let Some(table): Option<TableId> =
            TableId::from_index(u8::try_from(token >> 24).unwrap_or(0xFF))
        else {
            return;
        };
        match table {
            TableId::TypeDef => work.push(token),
            TableId::MethodDef => {
                if let Some(owner) = owner_of_method.get(&token) {
                    work.push(*owner);
                }
            }
            TableId::Field => {
                if let Some(owner) = owner_of_field.get(&token) {
                    work.push(*owner);
                }
            }
            TableId::TypeSpec => push_row_ref(
                resolver,
                RowRef {
                    table: TableId::TypeSpec,
                    row: token & 0x00FF_FFFF,
                },
                work,
            ),
            TableId::MemberRef => {
                let rid: usize = usize::try_from(token & 0x00FF_FFFF)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1);
                if let Some(member) = resolver.tables().member_refs.get(rid)
                    && let Some(parent) = member.parent
                {
                    let _: &MemberRefRow = member;
                    push_row_ref(resolver, parent, work);
                }
            }
            TableId::MethodSpec => {
                let rid: usize = usize::try_from(token & 0x00FF_FFFF)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1);
                if let Some(spec) = resolver.tables().method_specs.get(rid) {
                    let _: &MethodSpecRow = spec;
                    if let Some(method) = spec.method {
                        match method.table {
                            TableId::MethodDef => {
                                if let Some(owner) =
                                    owner_of_method.get(&(0x0600_0000 | method.row))
                                {
                                    work.push(*owner);
                                }
                            }
                            TableId::MemberRef => push_token(
                                resolver,
                                0x0A00_0000 | method.row,
                                owner_of_method,
                                owner_of_field,
                                work,
                            ),
                            _ => {}
                        }
                    }
                    if let Some(args) = resolver.method_spec_args(spec.instantiation) {
                        let mut tokens: Vec<u32> = Vec::new();
                        for arg in &args {
                            let _: &TypeSig = arg;
                            arg.collect_tokens(&mut tokens);
                        }
                        for t in tokens {
                            if t >> 24 == 0x02 {
                                work.push(t);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
