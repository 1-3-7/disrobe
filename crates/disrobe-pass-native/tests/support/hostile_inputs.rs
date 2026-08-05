use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct HostileInput {
    pub(crate) label: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) const HEADER_WINDOW: usize = 256;
pub(crate) const HEADER_MUTATION_STRIDE: usize = 8;
pub(crate) const BODY_MUTATION_SAMPLES: usize = 16;
pub(crate) const FIELD_EXTREME_SLOTS: usize = 8;

pub(crate) const SAMPLING_RULE: &str = "per base image: truncation at every power-of-two boundary \
     up to the length plus the quarter, half, three-quarter and last-byte boundaries; a 0xFF flip \
     at every eighth offset of the first 256 bytes; a 0xFF flip at 16 offsets spaced evenly through \
     the remainder; and 0x00000000, 0x80000000 and 0xFFFFFFFF written over eight four-byte-aligned \
     slots spaced evenly through the first 256 bytes. Exhaustive single-byte mutation is not \
     claimed and is not performed. The core sweep takes every sixth variant of each base; the deep \
     sweep takes every variant. Entry points marked expensive, which are the unpackers, the stub \
     emulator, the decompiler and the whole-image analyses, receive only inputs of 8192 bytes or \
     fewer, because one of them needs 103 seconds on a 22 kilobyte image and would otherwise turn \
     the suite into a benchmark; every truncation of a committed fixture below that cap still \
     reaches them.";

fn truncation_boundaries(len: usize) -> Vec<usize> {
    let mut cuts: Vec<usize> = vec![0];
    let mut step: usize = 1;
    while step < len {
        cuts.push(step);
        step = step.saturating_mul(2);
    }
    cuts.push(len / 4);
    cuts.push(len / 2);
    cuts.push(len.saturating_mul(3) / 4);
    cuts.push(len.saturating_sub(1));
    cuts.retain(|cut: &usize| *cut <= len);
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

fn push_variant(out: &mut Vec<HostileInput>, label: String, bytes: Vec<u8>) {
    out.push(HostileInput { label, bytes });
}

pub(crate) fn variants_of(name: &str, base: &[u8]) -> Vec<HostileInput> {
    let mut out: Vec<HostileInput> = Vec::new();
    push_variant(out.as_mut(), format!("{name}/whole"), base.to_vec());

    for cut in truncation_boundaries(base.len()) {
        push_variant(
            &mut out,
            format!("{name}/truncated@{cut}"),
            base[..cut].to_vec(),
        );
    }

    let header_end: usize = HEADER_WINDOW.min(base.len());
    for offset in (0..header_end).step_by(HEADER_MUTATION_STRIDE) {
        let mut mutated: Vec<u8> = base.to_vec();
        if let Some(slot) = mutated.get_mut(offset) {
            *slot ^= 0xFF;
        }
        push_variant(&mut out, format!("{name}/flip@{offset}"), mutated);
    }

    if base.len() > header_end {
        let span: usize = base.len() - header_end;
        let stride: usize = (span / BODY_MUTATION_SAMPLES).max(1);
        for index in 0..BODY_MUTATION_SAMPLES {
            let offset: usize = header_end + index * stride;
            if offset >= base.len() {
                break;
            }
            let mut mutated: Vec<u8> = base.to_vec();
            if let Some(slot) = mutated.get_mut(offset) {
                *slot ^= 0xFF;
            }
            push_variant(&mut out, format!("{name}/body-flip@{offset}"), mutated);
        }
    }

    let slot_stride: usize = (header_end / FIELD_EXTREME_SLOTS).max(4) & !3;
    for slot in 0..FIELD_EXTREME_SLOTS {
        let offset: usize = slot * slot_stride;
        if offset + 4 > base.len() {
            break;
        }
        for (tag, value) in [
            ("zero", 0u32),
            ("high", 0x8000_0000u32),
            ("max", 0xFFFF_FFFFu32),
        ] {
            let mut mutated: Vec<u8> = base.to_vec();
            if let Some(window) = mutated.get_mut(offset..offset + 4) {
                window.copy_from_slice(&value.to_le_bytes());
            }
            push_variant(&mut out, format!("{name}/{tag}@{offset}"), mutated);
        }
    }

    out
}

pub(crate) fn crafted_pe32_plus() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    buf[0x98..0x9A].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[0x98 + 24..0x98 + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    buf[0x98 + 56..0x98 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    buf[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
    let section: usize = 0x98 + 0xF0;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    buf
}

pub(crate) fn crafted_pe32() -> Vec<u8> {
    let mut buf: Vec<u8> = crafted_pe32_plus();
    buf[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf
}

pub(crate) fn crafted_elf(bits64: bool, little_endian: bool) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 512];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = if bits64 { 2 } else { 1 };
    buf[5] = if little_endian { 1 } else { 2 };
    buf[6] = 1;
    let put16 = |buf: &mut Vec<u8>, at: usize, value: u16| {
        let raw: [u8; 2] = if little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        buf[at..at + 2].copy_from_slice(&raw);
    };
    put16(&mut buf, 16, 2);
    if bits64 {
        put16(&mut buf, 18, 0x3E);
        put16(&mut buf, 52, 64);
        put16(&mut buf, 54, 56);
        put16(&mut buf, 56, 1);
        let phoff: [u8; 8] = if little_endian {
            64u64.to_le_bytes()
        } else {
            64u64.to_be_bytes()
        };
        buf[32..40].copy_from_slice(&phoff);
    } else {
        put16(&mut buf, 18, 3);
        put16(&mut buf, 40, 52);
        put16(&mut buf, 42, 32);
        put16(&mut buf, 44, 1);
        let phoff: [u8; 4] = if little_endian {
            52u32.to_le_bytes()
        } else {
            52u32.to_be_bytes()
        };
        buf[28..32].copy_from_slice(&phoff);
    }
    buf
}

pub(crate) fn crafted_macho_thin() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    buf[12..16].copy_from_slice(&2u32.to_le_bytes());
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    buf[20..24].copy_from_slice(&72u32.to_le_bytes());
    buf[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    buf[36..40].copy_from_slice(&72u32.to_le_bytes());
    buf
}

pub(crate) fn crafted_macho_fat() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
    buf[20..24].copy_from_slice(&128u32.to_be_bytes());
    buf[24..28].copy_from_slice(&64u32.to_be_bytes());
    buf[128..132].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf
}

pub(crate) fn crafted_flat_image() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0x90u8; 4096];
    buf[0..8].copy_from_slice(&0xFFFF_FFFB_0000_0000u64.to_le_bytes());
    buf
}

pub(crate) fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root: &Path| root.join("corpus").join("native"))
        .unwrap_or_default()
}

pub(crate) fn committed_image(relative: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_root().join(relative)).ok()
}

pub(crate) const COMPILED_VM_PROBE: &str = "<a virtual machine probe compiled by clang>";

fn clang_path() -> Option<String> {
    ["clang", "clang-18", "clang-17"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|out: std::process::Output| out.status.success())
        })
        .map(str::to_owned)
}

pub(crate) fn compiled_vm_probe() -> Option<Vec<u8>> {
    let clang: String = clang_path()?;
    let fixture: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vm_oracle.c");
    let template: String = std::fs::read_to_string(&fixture).ok()?;
    let out_dir: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("resilience_vm_probe");
    std::fs::create_dir_all(&out_dir).ok()?;

    let mut inc: String = String::new();
    for index in 0..256u32 {
        if index % 16 == 0 {
            inc.push_str("\n    ");
        }
        let byte: u8 = index as u8;
        let _ = write!(inc, "0x{byte:02x}, ");
    }
    inc.push('\n');
    let inc_path: PathBuf = out_dir.join("resilience_bytecode.inc");
    std::fs::write(&inc_path, inc).ok()?;

    let source_path: PathBuf = out_dir.join("resilience_vm.c");
    let patched: String = template.replace(
        "#include \"vm_oracle_bytecode.inc\"",
        "#include \"resilience_bytecode.inc\"",
    );
    std::fs::write(&source_path, patched).ok()?;

    let binary: PathBuf = out_dir.join(if cfg!(windows) {
        "resilience_vm.exe"
    } else {
        "resilience_vm"
    });
    let built: std::process::Output = std::process::Command::new(&clang)
        .args(["-O1", "-fno-inline"])
        .arg(&source_path)
        .arg("-o")
        .arg(&binary)
        .output()
        .ok()?;
    if !built.status.success() {
        return None;
    }
    std::fs::read(&binary).ok()
}
