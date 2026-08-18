#![cfg(feature = "chain")]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotReport, AotRuntime, ReadyToRunHeader, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/managed_abi_net9_x86_64.exe");
const SOURCE: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.csproj.txt");
const BUILD: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.build.txt");
const LINK_MAP: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.unwind.txt");
const DISASM: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.disasm.txt");

const FP_IMAGE: &[u8] = include_bytes!("fixtures/native_aot/managed_abi_fp_net9_x86_64.exe");
const FP_SOURCE: &str = include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.cs");
const FP_PROJECT: &str = include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.csproj.txt");
const FP_BUILD: &str = include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.build.txt");
const FP_LINK_MAP: &str =
    include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.link.map.txt");
const FP_UNWIND: &str = include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.unwind.txt");
const FP_DISASM: &str = include_str!("fixtures/native_aot/managed_abi_fp_net9_x86_64.disasm.txt");

const AMD64_MACHINE: u16 = 0x8664;
const MS_X64_INTEGER_REGISTERS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
const INSTANCE_REFERENCE_C_TYPE: &str = "uintptr_t";
const VOID_MANAGED_TYPE: &str = "System.Void";
const BOOLEAN_MANAGED_TYPE: &str = "System.Boolean";
const STDINT_INCLUDE: &str = "#include <stdint.h>\n";
const STDBOOL_AND_STDINT_INCLUDE: &str = "#include <stdbool.h>\n#include <stdint.h>\n";

const MANAGED_TO_C: [(&str, &str); 14] = [
    ("System.Boolean", "bool"),
    ("System.SByte", "int8_t"),
    ("System.Byte", "uint8_t"),
    ("System.Int16", "int16_t"),
    ("System.UInt16", "uint16_t"),
    ("System.Char", "uint16_t"),
    ("System.Int32", "int32_t"),
    ("System.UInt32", "uint32_t"),
    ("System.Int64", "int64_t"),
    ("System.UInt64", "uint64_t"),
    ("System.IntPtr", "intptr_t"),
    ("System.UIntPtr", "uintptr_t"),
    ("System.Single", "float"),
    ("System.Double", "double"),
];
const MANAGED_TO_UNSIGNED_C: [(&str, &str); 12] = [
    ("System.Boolean", "uint8_t"),
    ("System.SByte", "uint8_t"),
    ("System.Byte", "uint8_t"),
    ("System.Int16", "uint16_t"),
    ("System.UInt16", "uint16_t"),
    ("System.Char", "uint16_t"),
    ("System.Int32", "uint32_t"),
    ("System.UInt32", "uint32_t"),
    ("System.Int64", "uint64_t"),
    ("System.UInt64", "uint64_t"),
    ("System.IntPtr", "uintptr_t"),
    ("System.UIntPtr", "uintptr_t"),
];
const MANAGED_SIGN_REINTERPRETED: [&str; 6] = [
    "System.Boolean",
    "System.SByte",
    "System.Int16",
    "System.Int32",
    "System.Int64",
    "System.IntPtr",
];
const MANAGED_FLOATING_POINT: [&str; 2] = ["System.Single", "System.Double"];

struct Evidence {
    image: &'static [u8],
    build: &'static str,
    link_map: &'static str,
    unwind: &'static str,
    disasm: &'static str,
    link_symbol_prefix: &'static str,
    declaring_type: &'static str,
}

const BASELINE: Evidence = Evidence {
    image: IMAGE,
    build: BUILD,
    link_map: LINK_MAP,
    unwind: UNWIND,
    disasm: DISASM,
    link_symbol_prefix: "managed_abi_net9_x86_64_ManagedAbiProbe__",
    declaring_type: "ManagedAbiProbe",
};
const FLOATING_POINT: Evidence = Evidence {
    image: FP_IMAGE,
    build: FP_BUILD,
    link_map: FP_LINK_MAP,
    unwind: FP_UNWIND,
    disasm: FP_DISASM,
    link_symbol_prefix: "managed_abi_fp_net9_x86_64_ManagedFpAbiProbe__",
    declaring_type: "ManagedFpAbiProbe",
};

const PROBE_METHODS: [(&str, &str); 7] = [
    ("Add", "Add"),
    ("Negate", "Negate"),
    ("Widen", "Widen"),
    ("IsPositive", "IsPositive"),
    ("Mask", "Mask"),
    ("Blend", "Blend"),
    ("Scale", "Scale"),
];
const FP_PROBE_METHODS: [(&str, &str); 12] = [
    ("_ctor", ".ctor"),
    ("AddDouble", "AddDouble"),
    ("ScaleFloat", "ScaleFloat"),
    ("Promote", "Promote"),
    ("Weight", "Weight"),
    ("Offset", "Offset"),
    ("Mix", "Mix"),
    ("SetSlot", "SetSlot"),
    ("SetRatio", "SetRatio"),
    ("Clear", "Clear"),
    ("Store", "Store"),
    ("Split", "Split"),
];
const FP_REATTACHED_METHODS: [(&str, &str); 11] = [
    ("_ctor", ".ctor"),
    ("AddDouble", "AddDouble"),
    ("ScaleFloat", "ScaleFloat"),
    ("Promote", "Promote"),
    ("Weight", "Weight"),
    ("Offset", "Offset"),
    ("Mix", "Mix"),
    ("SetSlot", "SetSlot"),
    ("SetRatio", "SetRatio"),
    ("Clear", "Clear"),
    ("Store", "Store"),
];

const EXPECTED_BODIES: [(&str, &str); 7] = [
    (
        "Add",
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Negate",
        "#include <stdint.h>\nint32_t recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx) & 0xffffffffULL;\n    r_rax = ((uint64_t)-(int64_t)r_rax) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Widen",
        "#include <stdint.h>\nint64_t recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = (uint64_t)(int64_t)(int32_t)((r_rcx) & 0xffffffffULL);\n    return (int64_t)(uint64_t)(r_rax);\n}\n",
    ),
    (
        "IsPositive",
        "#include <stdbool.h>\n#include <stdint.h>\nbool recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = r_rax & 0xffffffffffffff00ULL | (uint64_t)(((int64_t)(int32_t)(r_rcx) > 0) ? 1 : 0);\n    r_rax = ((uint32_t)(uint8_t)((r_rax) & 0xffULL)) & 0xffffffffULL;\n    return (bool)(uint8_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Mask",
        "#include <stdint.h>\nuint32_t recovered(uint32_t a0, uint8_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx) & 0xffffffffULL;\n    r_rcx = ((uint32_t)(uint8_t)((r_rdx) & 0xffULL)) & 0xffffffffULL;\n    r_rax = ((r_rax & 0xffffffffULL) >> (((r_rcx & 0xffULL)) & 31)) & 0xffffffffULL;\n    return (uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Blend",
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1, int32_t a2, int32_t a3) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_r8 = (uint32_t)a2;\n    uint64_t r_r9 = (uint32_t)a3;\n    uint64_t r_rax = 0;\n    r_rdx = (r_rdx + (r_rdx)) & 0xffffffffULL;\n    r_rcx = (r_rcx + (r_rdx)) & 0xffffffffULL;\n    r_rax = (r_r8 + r_r8 * 2ULL) & 0xffffffffULL;\n    r_rax = (r_rax + (r_rcx)) & 0xffffffffULL;\n    r_rax = (r_rax + r_r9 * 4ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Scale",
        "#include <stdint.h>\nint32_t recovered(uintptr_t a0, int32_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rdx) & 0xffffffffULL;\n    r_rax = (r_rax * ((uint64_t)(*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)8LL)))) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
];

const FP_PREAMBLE: &str = "#include <stdint.h>\n#include <string.h>\nstatic inline double fp_d_from_bits(uint64_t b){ double v; memcpy(&v,&b,8); return v; }\nstatic inline uint64_t fp_d_to_bits(double v){ uint64_t b; memcpy(&b,&v,8); return b; }\nstatic inline float fp_f_from_bits(uint32_t b){ float v; memcpy(&v,&b,4); return v; }\nstatic inline uint32_t fp_f_to_bits(float v){ uint32_t b; memcpy(&b,&v,4); return b; }\n";

const FP_EXPECTED_BODIES: [(&str, &str); 12] = [
    (
        "_ctor",
        "#include <stdint.h>\nvoid recovered(uintptr_t a0, int32_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    (*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)16LL)) = (r_rdx) & 0xffffffffULL;\n}\n",
    ),
    (
        "AddDouble",
        "double recovered(double a0, double a1) {\n    uint64_t x_xmm0 = fp_d_to_bits((double)(a0));\n    uint64_t x_xmm1 = fp_d_to_bits((double)(a1));\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1)));\n    return fp_d_from_bits(x_xmm0);\n}\n",
    ),
    (
        "ScaleFloat",
        "float recovered(float a0, float a1) {\n    uint64_t x_xmm0 = (uint64_t)fp_f_to_bits((float)(a0));\n    uint64_t x_xmm1 = (uint64_t)fp_f_to_bits((float)(a1));\n    x_xmm0 = (uint64_t)fp_f_to_bits((float)(fp_f_from_bits((uint32_t)x_xmm0) * fp_f_from_bits((uint32_t)x_xmm1)));\n    return fp_f_from_bits((uint32_t)x_xmm0);\n}\n",
    ),
    (
        "Promote",
        "double recovered(float a0) {\n    uint64_t x_xmm0 = (uint64_t)fp_f_to_bits((float)(a0));\n    x_xmm0 = fp_d_to_bits((double)(fp_f_from_bits((uint32_t)x_xmm0)));\n    return fp_d_from_bits(x_xmm0);\n}\n",
    ),
    (
        "Weight",
        "float recovered(int32_t a0, float a1, float a2) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t x_xmm1 = (uint64_t)fp_f_to_bits((float)(a1));\n    uint64_t x_xmm2 = (uint64_t)fp_f_to_bits((float)(a2));\n    uint64_t x_xmm0 = 0;\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(0x0ULL)));\n    x_xmm0 = (uint64_t)fp_f_to_bits((float)((int32_t)r_rcx));\n    x_xmm0 = (uint64_t)fp_f_to_bits((float)(fp_f_from_bits((uint32_t)x_xmm0) * fp_f_from_bits((uint32_t)x_xmm1)));\n    x_xmm0 = (uint64_t)fp_f_to_bits((float)(fp_f_from_bits((uint32_t)x_xmm0) + fp_f_from_bits((uint32_t)x_xmm2)));\n    return fp_f_from_bits((uint32_t)x_xmm0);\n}\n",
    ),
    (
        "Offset",
        "double recovered(double a0, int32_t a1) {\n    uint64_t x_xmm0 = fp_d_to_bits((double)(a0));\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t x_xmm1 = 0;\n    x_xmm1 = fp_d_to_bits((double)(fp_d_from_bits(0x0ULL)));\n    x_xmm1 = fp_d_to_bits((double)((int32_t)r_rdx));\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1)));\n    return fp_d_from_bits(x_xmm0);\n}\n",
    ),
    (
        "Mix",
        "double recovered(double a0, float a1, int32_t a2, double a3) {\n    uint64_t x_xmm0 = fp_d_to_bits((double)(a0));\n    uint64_t x_xmm1 = (uint64_t)fp_f_to_bits((float)(a1));\n    uint64_t r_r8 = (uint32_t)a2;\n    uint64_t x_xmm3 = fp_d_to_bits((double)(a3));\n    x_xmm1 = fp_d_to_bits((double)(fp_f_from_bits((uint32_t)x_xmm1)));\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1)));\n    x_xmm1 = fp_d_to_bits((double)(fp_d_from_bits(0x0ULL)));\n    x_xmm1 = fp_d_to_bits((double)((int32_t)r_r8));\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1)));\n    x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm3)));\n    return fp_d_from_bits(x_xmm0);\n}\n",
    ),
    (
        "SetSlot",
        "#include <stdint.h>\nvoid recovered(uintptr_t a0, int32_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    (*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)16LL)) = (r_rdx) & 0xffffffffULL;\n}\n",
    ),
    (
        "SetRatio",
        "void recovered(uintptr_t a0, double a1) {\n    uint64_t r_rcx = a0;\n    uint64_t x_xmm1 = fp_d_to_bits((double)(a1));\n    (*(uint64_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)8LL)) = x_xmm1;\n}\n",
    ),
    (
        "Clear",
        "#include <stdint.h>\nvoid recovered(uintptr_t a0) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rax = 0;\n    r_rax = ((uint64_t)(int64_t)0LL) & 0xffffffffULL;\n    (*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)16LL)) = (r_rax) & 0xffffffffULL;\n}\n",
    ),
    (
        "Store",
        "#include <stdint.h>\nvoid recovered(intptr_t a0, int32_t a1) {\n    uint64_t r_rcx = (uintptr_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    (*(uint32_t*)(uintptr_t)(r_rcx)) = (r_rdx) & 0xffffffffULL;\n}\n",
    ),
    (
        "Split",
        "#include <stdint.h>\ntypedef struct {\n    uint64_t f0;\n    uint64_t f1;\n} recovered_sret_t;\nrecovered_sret_t recovered(uint64_t a0) {\n    recovered_sret_t __sret;\n    uint64_t r_rdx = a0;\n    uint64_t r_rax = 0;\n    uint64_t r_rcx = (uint64_t)(uintptr_t)&__sret;\n    r_rax = ((uint32_t)(uint16_t)((r_rdx) & 0xffffULL)) & 0xffffffffULL;\n    r_rdx = (uint64_t)((int64_t)(int64_t)r_rdx >> (((uint64_t)(int64_t)16LL) & 63));\n    (*(uint64_t*)(uintptr_t)(r_rcx)) = r_rax;\n    (*(uint64_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)8LL)) = r_rdx;\n    r_rax = r_rcx;\n    return __sret;\n}\n",
    ),
];

fn c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    MANAGED_TO_C
        .iter()
        .find(|(name, _rendered): &&(&str, &str)| *name == managed)
        .map(|(_name, rendered): &(&str, &str)| *rendered)
        .ok_or("the declared managed type has no C99 equivalent in this grader")
}

fn unsigned_c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    MANAGED_TO_UNSIGNED_C
        .iter()
        .find(|(name, _rendered): &&(&str, &str)| *name == managed)
        .map(|(_name, rendered): &(&str, &str)| *rendered)
        .ok_or("the declared managed type has no unsigned C99 equivalent in this grader")
}

fn return_c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    if managed == VOID_MANAGED_TYPE {
        return Ok("void");
    }
    c_type_for(managed)
}

fn is_floating_point(managed: &str) -> bool {
    MANAGED_FLOATING_POINT.contains(&managed)
}

fn expected_binding_fragments(
    index: usize,
    slot: Option<&str>,
) -> Result<Vec<String>, &'static str> {
    let Some(managed): Option<&str> = slot else {
        let register: &str = MS_X64_INTEGER_REGISTERS
            .get(index)
            .copied()
            .ok_or("the instance reference exceeds the Microsoft x64 integer positions")?;
        return Ok(vec![format!("    uint64_t r_{register} = a{index};\n")]);
    };
    if is_floating_point(managed) {
        let rendered: &'static str = c_type_for(managed)?;
        return Ok(vec![
            format!("    uint64_t x_xmm{index} = "),
            format!("({rendered})(a{index}))"),
        ]);
    }
    let register: &str = MS_X64_INTEGER_REGISTERS
        .get(index)
        .copied()
        .ok_or("the declared argument exceeds the Microsoft x64 integer positions")?;
    if MANAGED_SIGN_REINTERPRETED.contains(&managed) {
        let unsigned: &'static str = unsigned_c_type_for(managed)?;
        return Ok(vec![format!(
            "    uint64_t r_{register} = ({unsigned})a{index};\n"
        )]);
    }
    Ok(vec![format!("    uint64_t r_{register} = a{index};\n")])
}

impl Evidence {
    fn compiler_load_address(&self) -> Result<u64, &'static str> {
        let text: &str = self
            .link_map
            .lines()
            .find_map(|line: &str| {
                line.split_once("Preferred load address is ")
                    .map(|(_head, value): (&str, &str)| value)
            })
            .ok_or("compiler map load address is absent")?;
        u64::from_str_radix(text.trim(), 16)
            .map_err(|_: std::num::ParseIntError| "compiler map load address is malformed")
    }

    fn compiler_method_rva(&self, key: &str) -> Result<u32, &'static str> {
        let symbol: String = format!("{}{key}", self.link_symbol_prefix);
        let address_text: &str = self
            .link_map
            .lines()
            .find_map(|line: &str| {
                let mut fields: std::str::SplitWhitespace<'_> = line.split_whitespace();
                let _section: &str = fields.next()?;
                if fields.next()? != symbol {
                    return None;
                }
                fields.next()
            })
            .ok_or("compiler map method address is absent")?;
        let address: u64 = u64::from_str_radix(address_text, 16)
            .map_err(|_: std::num::ParseIntError| "compiler map method address is malformed")?;
        let rva: u64 = address
            .checked_sub(self.compiler_load_address()?)
            .ok_or("compiler map address precedes the image base")?;
        u32::try_from(rva)
            .map_err(|_: std::num::TryFromIntError| "compiler map RVA does not fit u32")
    }

    fn evidence_range(&self, key: &str) -> Result<(u32, u32), &'static str> {
        let symbol: String = format!("{}{key}", self.link_symbol_prefix);
        let mut found: Option<(u32, u32)> = None;
        for line in self.unwind.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 5 || *fields.last().unwrap_or(&"") != symbol {
                continue;
            }
            let begin: u32 = u32::from_str_radix(fields.get(1).unwrap_or(&""), 16)
                .map_err(|_: std::num::ParseIntError| "unwind begin RVA is malformed")?;
            let end: u32 = u32::from_str_radix(fields.get(2).unwrap_or(&""), 16)
                .map_err(|_: std::num::ParseIntError| "unwind end RVA is malformed")?;
            if found.is_some() {
                return Err("unwind evidence names the method more than once");
            }
            found = Some((begin, end));
        }
        found.ok_or("unwind evidence for the method is absent")
    }

    fn evidence_bytes(&self, key: &str) -> Result<Vec<u8>, &'static str> {
        let header: String = format!("# {}.{key} [", self.declaring_type);
        let mut bytes: Vec<u8> = Vec::new();
        let mut inside: bool = false;
        for line in self.disasm.lines() {
            if line.starts_with('#') {
                if inside {
                    break;
                }
                inside = line.starts_with(header.as_str());
                continue;
            }
            if !inside {
                continue;
            }
            let (_address, remainder): (&str, &str) = line
                .split_once(':')
                .ok_or("disassembly evidence line has no address")?;
            let encoded: &str = remainder
                .split('\t')
                .next()
                .ok_or("disassembly evidence line has no encoding")?;
            for token in encoded.split_whitespace() {
                bytes.push(
                    u8::from_str_radix(token, 16)
                        .map_err(|_: std::num::ParseIntError| "disassembly byte is malformed")?,
                );
            }
        }
        if bytes.is_empty() {
            return Err("disassembly evidence for the method is absent");
        }
        Ok(bytes)
    }

    fn declared_managed_signature(
        &self,
        key: &str,
    ) -> Result<(bool, &'static str, Vec<&'static str>), &'static str> {
        let prefix: String = format!("{}.{key} managed signature: ", self.declaring_type);
        let declaration: &'static str = self
            .build
            .lines()
            .find_map(|line: &'static str| line.strip_prefix(prefix.as_str()))
            .ok_or("build evidence does not declare the managed signature")?;
        let (kind, remainder): (&str, &'static str) = declaration
            .split_once(' ')
            .ok_or("declared managed signature has no receiver kind")?;
        let has_this: bool = match kind {
            "instance" => true,
            "static" => false,
            _other => return Err("declared managed signature has an unknown receiver kind"),
        };
        let (return_type, remainder): (&'static str, &'static str) = remainder
            .split_once(' ')
            .ok_or("declared managed signature has no return type")?;
        let parameters: &'static str = remainder
            .split_once('(')
            .and_then(|(_name, tail): (&str, &'static str)| tail.strip_suffix(')'))
            .ok_or("declared managed signature has no parameter list")?;
        let managed: Vec<&'static str> = parameters
            .split(',')
            .map(str::trim)
            .filter(|parameter: &&str| !parameter.is_empty())
            .collect();
        Ok((has_this, return_type, managed))
    }

    fn declared_slots(&self, key: &str) -> Result<Vec<Option<&'static str>>, &'static str> {
        let (has_this, _return_type, parameters): (bool, &'static str, Vec<&'static str>) =
            self.declared_managed_signature(key)?;
        let mut slots: Vec<Option<&'static str>> = Vec::new();
        if has_this {
            slots.push(None);
        }
        slots.extend(parameters.into_iter().map(Some));
        Ok(slots)
    }

    fn expected_prototype_line(&self, key: &str) -> Result<String, &'static str> {
        let (_has_this, return_type, _parameters): (bool, &'static str, Vec<&'static str>) =
            self.declared_managed_signature(key)?;
        let slots: Vec<Option<&'static str>> = self.declared_slots(key)?;
        let mut rendered: Vec<String> = Vec::new();
        for (index, slot) in slots.iter().enumerate() {
            let c_type: &'static str = match slot {
                None => INSTANCE_REFERENCE_C_TYPE,
                Some(managed) => c_type_for(managed)?,
            };
            rendered.push(format!("{c_type} a{index}"));
        }
        let parameters: String = if rendered.is_empty() {
            "void".to_owned()
        } else {
            rendered.join(", ")
        };
        Ok(format!(
            "{} recovered({parameters}) {{\n",
            return_c_type_for(return_type)?
        ))
    }

    fn expected_include_prefix(&self, key: &str) -> Result<&'static str, &'static str> {
        let (_has_this, return_type, parameters): (bool, &'static str, Vec<&'static str>) =
            self.declared_managed_signature(key)?;
        let uses_boolean: bool =
            return_type == BOOLEAN_MANAGED_TYPE || parameters.contains(&BOOLEAN_MANAGED_TYPE);
        Ok(if uses_boolean {
            STDBOOL_AND_STDINT_INCLUDE
        } else {
            STDINT_INCLUDE
        })
    }

    fn document(&self) -> Result<serde_json::Value, &'static str> {
        let input: Artifact = Artifact::new(Rung::Raw, self.image.to_vec(), [0u8; 32]);
        let output: Artifact = DOTNET_PASS.run(&input).map_err(
            |_: disrobe_core::error::CoreError| "the auto route refused the NativeAOT image",
        )?;
        serde_json::from_slice(&output.envelope)
            .map_err(|_: serde_json::Error| "the NativeAOT artifact is not JSON")
    }
}

fn method_record<'document>(
    document: &'document serde_json::Value,
    declaring_type: &str,
    name: &str,
) -> Result<&'document serde_json::Value, &'static str> {
    document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == declaring_type && method["name"] == name
            })
        })
        .ok_or("the compiler-emitted method is absent from the auto artifact")
}

fn recovered_pseudo_c<'document>(
    document: &'document serde_json::Value,
    declaring_type: &str,
    name: &str,
) -> Result<&'document str, &'static str> {
    method_record(document, declaring_type, name)?["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")
}

fn verify_compiler_evidence(
    evidence: &Evidence,
    methods: &[(&str, &str)],
) -> Result<(), &'static str> {
    let pe: PeImage = parse(evidence.image)
        .map_err(|_: disrobe_pass_dotnet::Error| "the fixture is not a PE image")?;
    assert_eq!(
        (pe.bitness, pe.machine),
        (PeBitness::Pe32Plus, AMD64_MACHINE)
    );
    assert_eq!(pe.image_base, evidence.compiler_load_address()?);
    for (key, _name) in methods {
        let start_rva: u32 = evidence.compiler_method_rva(key)?;
        let (begin, end): (u32, u32) = evidence.evidence_range(key)?;
        assert_eq!(begin, start_rva, "{key}");
        let bytes: Vec<u8> = evidence.evidence_bytes(key)?;
        assert_eq!(
            u32::try_from(bytes.len())
                .map_err(|_: std::num::TryFromIntError| "evidence byte count does not fit u32")?,
            end.checked_sub(begin)
                .ok_or("the unwind range for the method is reversed")?,
            "{key}"
        );
        let offset: usize = pe
            .rva_to_offset(start_rva)
            .ok_or("the compiler method body is not file backed")?;
        let end_offset: usize = offset
            .checked_add(bytes.len())
            .ok_or("the compiler method body end overflowed")?;
        assert_eq!(
            evidence.image.get(offset..end_offset),
            Some(bytes.as_slice()),
            "{key}"
        );
    }
    Ok(())
}

fn verify_reattached_signature(
    evidence: &Evidence,
    document: &serde_json::Value,
    key: &str,
    name: &str,
) -> Result<(), &'static str> {
    let method: &serde_json::Value = method_record(document, evidence.declaring_type, name)?;
    let start_rva: u32 = evidence.compiler_method_rva(key)?;
    let (begin, end): (u32, u32) = evidence.evidence_range(key)?;
    assert_eq!(method["entrypoint_rva"], start_rva, "{key}");
    assert_eq!(method["code_range"]["start_rva"], begin, "{key}");
    assert_eq!(method["code_range"]["end_rva"], end, "{key}");
    assert_eq!(method["body"]["status"], "recovered", "{key}");
    let pseudo_c: &str = method["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")?;
    assert!(
        pseudo_c.starts_with(evidence.expected_include_prefix(key)?),
        "{key}: {pseudo_c}"
    );
    let prototype: String = evidence.expected_prototype_line(key)?;
    assert_eq!(
        pseudo_c.matches(prototype.as_str()).count(),
        1,
        "{key} must carry the declared managed prototype {prototype} exactly once: {pseudo_c}"
    );
    let preamble: &str = pseudo_c
        .split(prototype.as_str())
        .next()
        .ok_or("the recovered body has no preamble")?;
    assert!(
        preamble
            .lines()
            .all(|line: &str| line.starts_with("#include ") || line.starts_with("static inline ")),
        "{key} must place the managed prototype ahead of every statement: {preamble}"
    );
    for (index, slot) in evidence.declared_slots(key)?.iter().enumerate() {
        for fragment in expected_binding_fragments(index, *slot)? {
            assert!(
                pseudo_c.contains(fragment.as_str()),
                "{key} must bind argument {index} through {fragment}: {pseudo_c}"
            );
        }
    }
    Ok(())
}

#[test]
fn the_fixture_carries_the_compiler_evidence_it_is_graded_against() -> Result<(), &'static str> {
    assert!(SOURCE.contains("public static int Add(int left, int right) => left + right;"));
    assert!(SOURCE.contains("public static long Widen(int value) => value;"));
    assert!(SOURCE.contains("public static bool IsPositive(int value) => value > 0;"));
    assert!(SOURCE.contains("public static uint Mask(uint value, byte shift) => value >> shift;"));
    assert!(SOURCE.contains("public int Scale(int value) => value * this.factor;"));
    assert!(PROJECT.contains("<TargetFramework>net9.0</TargetFramework>"));
    assert!(PROJECT.contains("<PublishAot>true</PublishAot>"));
    assert!(BUILD.contains("Compiler: Microsoft.DotNet.ILCompiler 9.0.18"));
    assert!(BUILD.contains("HASTHIS 0x20"));

    verify_compiler_evidence(&BASELINE, &PROBE_METHODS)
}

#[test]
fn the_floating_point_fixture_carries_the_compiler_evidence_it_is_graded_against()
-> Result<(), &'static str> {
    assert!(
        FP_SOURCE
            .contains("public static double AddDouble(double left, double right) => left + right;")
    );
    assert!(
        FP_SOURCE.contains(
            "public static float ScaleFloat(float value, float factor) => value * factor;"
        )
    );
    assert!(FP_SOURCE.contains("public static double Promote(float value) => value;"));
    assert!(FP_SOURCE.contains("public void SetSlot(int value) => this.Slot = value;"));
    assert!(FP_SOURCE.contains("public void SetRatio(double ratio) => this.Ratio = ratio;"));
    assert!(FP_SOURCE.contains(
        "public static unsafe void Store(IntPtr target, int value) => *(int*)target = value;"
    ));
    assert!(FP_SOURCE.contains("public ManagedFpAbiProbe(int slot) => this.Slot = slot;"));
    assert!(FP_PROJECT.contains("<TargetFramework>net9.0</TargetFramework>"));
    assert!(FP_PROJECT.contains("<PublishAot>true</PublishAot>"));
    assert!(FP_BUILD.contains("Compiler: Microsoft.DotNet.ILCompiler 9.0.18"));
    assert!(FP_BUILD.contains(
        "Microsoft x64 floating-point argument registers: XMM0, XMM1, XMM2, XMM3 for Single and \
         Double arguments"
    ));

    verify_compiler_evidence(&FLOATING_POINT, &FP_PROBE_METHODS)
}

#[test]
fn auto_reattaches_every_declared_managed_signature_to_its_body() -> Result<(), &'static str> {
    let document: serde_json::Value = BASELINE.document()?;
    assert_eq!(document["schema"], "disrobe.dotnet.native-aot-symbols/v1");
    assert_eq!(document["runtime"], "net9");

    for (key, name) in PROBE_METHODS {
        verify_reattached_signature(&BASELINE, &document, key, name)?;
        let expected: &str = EXPECTED_BODIES
            .iter()
            .find(|(candidate, _body): &&(&str, &str)| *candidate == key)
            .map(|(_candidate, body): &(&str, &str)| *body)
            .ok_or("the graded body for the method is absent")?;
        assert_eq!(
            recovered_pseudo_c(&document, BASELINE.declaring_type, name)?,
            expected,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn auto_reattaches_void_and_floating_point_signatures_to_their_bodies() -> Result<(), &'static str>
{
    let document: serde_json::Value = FLOATING_POINT.document()?;
    assert_eq!(document["schema"], "disrobe.dotnet.native-aot-symbols/v1");
    assert_eq!(document["runtime"], "net9");

    for (key, name) in FP_REATTACHED_METHODS {
        verify_reattached_signature(&FLOATING_POINT, &document, key, name)?;
        let expected: &str = FP_EXPECTED_BODIES
            .iter()
            .find(|(candidate, _body): &&(&str, &str)| *candidate == key)
            .map(|(_candidate, body): &(&str, &str)| *body)
            .ok_or("the graded body for the method is absent")?;
        let recovered: &str = recovered_pseudo_c(&document, FLOATING_POINT.declaring_type, name)?;
        let expected: String = if expected.starts_with("#include ") {
            expected.to_owned()
        } else {
            format!("{FP_PREAMBLE}{expected}")
        };
        assert_eq!(recovered, expected.as_str(), "{key}");
    }
    Ok(())
}

#[test]
fn a_void_return_drops_the_return_statement_and_its_dead_result_binding() -> Result<(), &'static str>
{
    let document: serde_json::Value = FLOATING_POINT.document()?;
    for (key, name) in [
        ("_ctor", ".ctor"),
        ("SetSlot", "SetSlot"),
        ("SetRatio", "SetRatio"),
        ("Clear", "Clear"),
        ("Store", "Store"),
    ] {
        let (_has_this, return_type, _parameters): (bool, &'static str, Vec<&'static str>) =
            FLOATING_POINT.declared_managed_signature(key)?;
        assert_eq!(return_type, VOID_MANAGED_TYPE, "{key}");
        let pseudo_c: &str = recovered_pseudo_c(&document, FLOATING_POINT.declaring_type, name)?;
        assert!(
            !pseudo_c.contains("    return "),
            "a void method keeps no return statement: {key}: {pseudo_c}"
        );
        assert!(pseudo_c.contains("void recovered("), "{key}: {pseudo_c}");
    }
    let dead: &str = recovered_pseudo_c(&document, FLOATING_POINT.declaring_type, "SetSlot")?;
    let live: &str = recovered_pseudo_c(&document, FLOATING_POINT.declaring_type, "Clear")?;

    assert!(
        !dead.contains("uint64_t r_rax"),
        "a result register that only fed the dropped return is removed: {dead}"
    );
    assert!(
        live.contains("    uint64_t r_rax = 0;\n"),
        "a result register the body still writes is preserved: {live}"
    );
    Ok(())
}

#[test]
fn a_hidden_struct_return_keeps_the_register_typed_body() -> Result<(), &'static str> {
    let document: serde_json::Value = FLOATING_POINT.document()?;
    let (_has_this, return_type, parameters): (bool, &'static str, Vec<&'static str>) =
        FLOATING_POINT.declared_managed_signature("Split")?;

    assert_eq!(return_type, "ManagedPair");
    assert_eq!(parameters, vec!["System.Int64"]);
    assert!(
        return_c_type_for(return_type).is_err(),
        "a struct larger than eight bytes has no scalar C99 equivalent, so the ABI is undetermined"
    );
    let pseudo_c: &str = recovered_pseudo_c(&document, FLOATING_POINT.declaring_type, "Split")?;
    assert!(
        pseudo_c.contains("recovered_sret_t recovered(uint64_t a0) {\n"),
        "a hidden struct return keeps the register-typed prototype: {pseudo_c}"
    );
    let attached: String = format!(
        "recovered({} a0)",
        c_type_for(parameters.first().copied().unwrap_or_default())?
    );
    assert!(
        !pseudo_c.contains(attached.as_str()),
        "the declared argument must not be attached across the hidden return pointer: {pseudo_c}"
    );
    Ok(())
}

#[test]
fn a_signature_outside_the_primitive_table_keeps_the_register_typed_body()
-> Result<(), &'static str> {
    let document: serde_json::Value = BASELINE.document()?;
    let reference_equals: &serde_json::Value =
        method_record(&document, "System.Object", "ReferenceEquals")?;
    assert_eq!(
        reference_equals["signature"]["calling_convention"], 0,
        "System.Object.ReferenceEquals is a static two-reference comparison"
    );
    assert_eq!(
        reference_equals["signature"]["parameter_types"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let pseudo_c: &str = reference_equals["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")?;

    assert!(
        pseudo_c
            .starts_with("#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n"),
        "an object-reference signature must keep the register-typed prototype: {pseudo_c}"
    );
    Ok(())
}

#[test]
fn the_runtime_label_comes_from_the_metadata_version_not_a_build_path() -> Result<(), &'static str>
{
    for image in [IMAGE, FP_IMAGE] {
        assert!(
            !image.windows(6).any(|window: &[u8]| window == b"net9.0"),
            "this fixture must not carry a target-framework marker string"
        );
        let report: AotReport = detect(image);
        let header: ReadyToRunHeader = report
            .ready_to_run
            .clone()
            .ok_or("the NativeAOT header is absent")?;
        assert_eq!((header.major_version, header.minor_version), (10, 1));
        assert_eq!(report.runtime_label, AotRuntime::Net9);
    }

    let report: AotReport = detect(IMAGE);
    let header: ReadyToRunHeader = report
        .ready_to_run
        .ok_or("the NativeAOT header is absent")?;
    let major_offset: usize = usize::try_from(header.file_offset)
        .map_err(|_: std::num::TryFromIntError| "the header offset does not fit usize")?
        .checked_add(4)
        .ok_or("the header major-version offset overflowed")?;
    let major_end: usize = major_offset
        .checked_add(2)
        .ok_or("the header major-version end overflowed")?;
    let mut unlisted: Vec<u8> = IMAGE.to_vec();
    unlisted
        .get_mut(major_offset..major_end)
        .ok_or("the header major-version field is truncated")?
        .copy_from_slice(&11u16.to_le_bytes());
    let unlisted_report: AotReport = detect(&unlisted);

    assert_eq!(
        unlisted_report
            .ready_to_run
            .as_ref()
            .map(|header: &ReadyToRunHeader| header.major_version),
        Some(11)
    );
    assert_eq!(unlisted_report.runtime_label, AotRuntime::Unknown);
    Ok(())
}
