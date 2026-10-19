#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, GoImage, analyze};

const PAYLOAD_MAIN: &str = r#"package main

import "fmt"

var payloadFn = payloadMarker

func payloadMarker() int { return 41 }

func main() { fmt.Println(payloadFn()) }
"#;

const HOST_MAIN: &str = r#"package main

import "fmt"

var hostFn = hostMarker

func hostMarker() int { return 42 }

func main() { fmt.Println(hostFn()) }
"#;

fn pe_section_table_offset(bytes: &[u8]) -> Option<(usize, usize)> {
    let pe_offset: usize =
        usize::try_from(u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?)).ok()?;
    if bytes.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let section_count: usize = usize::from(u16::from_le_bytes(
        bytes
            .get(pe_offset.checked_add(6)?..pe_offset.checked_add(8)?)?
            .try_into()
            .ok()?,
    ));
    let optional_len: usize = usize::from(u16::from_le_bytes(
        bytes
            .get(pe_offset.checked_add(20)?..pe_offset.checked_add(22)?)?
            .try_into()
            .ok()?,
    ));
    let table: usize = pe_offset.checked_add(24)?.checked_add(optional_len)?;
    let table_len: usize = section_count.checked_mul(40)?;
    bytes.get(table..table.checked_add(table_len)?)?;
    Some((table, section_count))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .and_then(|raw: &[u8]| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes)
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder: usize = value.checked_rem(alignment)?;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment.checked_sub(remainder)?)
    }
}

fn append_pe_rodata(bytes: &mut Vec<u8>, payload: &[u8]) -> bool {
    let (table, count): (usize, usize) = match pe_section_table_offset(bytes) {
        Some(value) => value,
        None => return false,
    };
    let pe_offset: usize =
        match pe_u32(bytes, 0x3c).and_then(|value: u32| usize::try_from(value).ok()) {
            Some(value) => value,
            None => return false,
        };
    let optional: usize = match pe_offset.checked_add(24) {
        Some(value) => value,
        None => return false,
    };
    let section_alignment: usize = match pe_u32(bytes, optional.saturating_add(32))
        .and_then(|value: u32| usize::try_from(value).ok())
    {
        Some(value) if value != 0 => value,
        _ => return false,
    };
    let file_alignment: usize = match pe_u32(bytes, optional.saturating_add(36))
        .and_then(|value: u32| usize::try_from(value).ok())
    {
        Some(value) if value != 0 => value,
        _ => return false,
    };
    let Some(headers_len): Option<usize> = pe_u32(bytes, optional.saturating_add(60))
        .and_then(|value: u32| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(entry): Option<usize> = table.checked_add(count.saturating_mul(40)) else {
        return false;
    };
    if entry.saturating_add(40) > headers_len {
        return false;
    }
    let mut virtual_end: usize = 0;
    for index in 0..count {
        let Some(section): Option<usize> = table.checked_add(index.saturating_mul(40)) else {
            return false;
        };
        let Some(address): Option<usize> = pe_u32(bytes, section.saturating_add(12))
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(size): Option<usize> = pe_u32(bytes, section.saturating_add(8))
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(end): Option<usize> = address.checked_add(size) else {
            return false;
        };
        virtual_end = virtual_end.max(end);
    }
    let Some(virtual_address): Option<usize> = align_up(virtual_end, section_alignment) else {
        return false;
    };
    let Some(raw_start): Option<usize> = align_up(bytes.len(), file_alignment) else {
        return false;
    };
    let Some(raw_len): Option<usize> = align_up(payload.len(), file_alignment) else {
        return false;
    };
    let Some(raw_end): Option<usize> = raw_start.checked_add(raw_len) else {
        return false;
    };
    let Some(virtual_end): Option<usize> = virtual_address.checked_add(payload.len()) else {
        return false;
    };
    let Some(size_of_image): Option<usize> = align_up(virtual_end, section_alignment) else {
        return false;
    };
    let Some(next_count): Option<usize> = count.checked_add(1) else {
        return false;
    };
    let Some(section_count): Option<u16> = u16::try_from(next_count).ok() else {
        return false;
    };
    let Some(raw_start_u32): Option<u32> = u32::try_from(raw_start).ok() else {
        return false;
    };
    let Some(raw_len_u32): Option<u32> = u32::try_from(raw_len).ok() else {
        return false;
    };
    let Some(payload_len_u32): Option<u32> = u32::try_from(payload.len()).ok() else {
        return false;
    };
    let Some(virtual_address_u32): Option<u32> = u32::try_from(virtual_address).ok() else {
        return false;
    };
    let Some(size_of_image_u32): Option<u32> = u32::try_from(size_of_image).ok() else {
        return false;
    };
    bytes.resize(raw_end, 0);
    bytes[entry..entry.saturating_add(8)].copy_from_slice(b".rodata\0");
    bytes[entry.saturating_add(8)..entry.saturating_add(12)]
        .copy_from_slice(&payload_len_u32.to_le_bytes());
    bytes[entry.saturating_add(12)..entry.saturating_add(16)]
        .copy_from_slice(&virtual_address_u32.to_le_bytes());
    bytes[entry.saturating_add(16)..entry.saturating_add(20)]
        .copy_from_slice(&raw_len_u32.to_le_bytes());
    bytes[entry.saturating_add(20)..entry.saturating_add(24)]
        .copy_from_slice(&raw_start_u32.to_le_bytes());
    bytes[entry.saturating_add(36)..entry.saturating_add(40)]
        .copy_from_slice(&0x4000_0040_u32.to_le_bytes());
    bytes[pe_offset.saturating_add(6)..pe_offset.saturating_add(8)]
        .copy_from_slice(&section_count.to_le_bytes());
    bytes[optional.saturating_add(56)..optional.saturating_add(60)]
        .copy_from_slice(&size_of_image_u32.to_le_bytes());
    bytes[raw_start..raw_start.saturating_add(payload.len())].copy_from_slice(payload);
    true
}

fn rename_pe_section(bytes: &mut [u8], old: [u8; 8], new: [u8; 8]) -> bool {
    let Some((table, count)): Option<(usize, usize)> = pe_section_table_offset(bytes) else {
        return false;
    };
    for index in 0..count {
        let Some(entry): Option<usize> = table.checked_add(index.saturating_mul(40)) else {
            return false;
        };
        if bytes.get(entry..entry.saturating_add(8)) == Some(old.as_slice()) {
            let Some(slot): Option<&mut [u8]> = bytes.get_mut(entry..entry.saturating_add(8))
            else {
                return false;
            };
            slot.copy_from_slice(&new);
            return true;
        }
    }
    false
}

fn patch_payload_reference(host: &mut [u8], payload_va: u64) -> bool {
    let (table, count): (usize, usize) = match pe_section_table_offset(host) {
        Some(value) => value,
        None => return false,
    };
    for index in 0..count {
        let Some(entry): Option<usize> = table.checked_add(index.saturating_mul(40)) else {
            return false;
        };
        if host.get(entry..entry.saturating_add(8)) != Some(b".data\0\0\0") {
            continue;
        }
        let Some(raw_len): Option<usize> = host
            .get(entry.saturating_add(16)..entry.saturating_add(20))
            .and_then(|raw: &[u8]| <[u8; 4]>::try_from(raw).ok())
            .map(|raw: [u8; 4]| u32::from_le_bytes(raw))
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(raw_start): Option<usize> = host
            .get(entry.saturating_add(20)..entry.saturating_add(24))
            .and_then(|raw: &[u8]| <[u8; 4]>::try_from(raw).ok())
            .map(|raw: [u8; 4]| u32::from_le_bytes(raw))
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(raw_end): Option<usize> = raw_start.checked_add(raw_len) else {
            return false;
        };
        let Some(data): Option<&mut [u8]> = host.get_mut(raw_start..raw_end) else {
            return false;
        };
        let Some(zero_run): Option<usize> = data
            .windows(32)
            .position(|window: &[u8]| window.iter().all(|byte: &u8| *byte == 0))
        else {
            return false;
        };
        let Some(slot): Option<&mut [u8]> =
            data.get_mut(zero_run.saturating_add(16)..zero_run.saturating_add(24))
        else {
            return false;
        };
        slot.copy_from_slice(&payload_va.to_le_bytes());
        return true;
    }
    false
}

#[test]
fn a_stripped_go_host_embedding_another_go_binary_reports_its_own_pclntab() {
    assert!(
        common::go_on_path(),
        "missing prerequisite: the Go toolchain (go on PATH, go1.26.3 in CI) builds this regression"
    );
    let payload_dir: common::GoBuildScratch = common::new_scratch("embedded_payload");
    common::write_module(&payload_dir, "example.com/payload", PAYLOAD_MAIN);
    let payload: PathBuf =
        common::go_build_cross_required(&payload_dir, "payload.exe", "windows", "amd64", &[])
            .unwrap_or_else(|error: String| panic!("{error}"));

    let host_dir: common::GoBuildScratch = common::new_scratch("embedding_host");
    common::write_module(&host_dir, "example.com/host", HOST_MAIN);
    let host: PathBuf = common::go_build_cross_required(
        &host_dir,
        "host.exe",
        "windows",
        "amd64",
        &["-ldflags=-s -w"],
    )
    .unwrap_or_else(|error: String| panic!("{error}"));

    let mut bytes: Vec<u8> = std::fs::read(&host).expect("read the host build");
    let payload_bytes: Vec<u8> = std::fs::read(&payload).expect("read the payload build");
    let payload_pclntab: usize =
        common::find_pclntab_offset(&payload_bytes).expect("the payload has a pclntab");
    assert!(
        rename_pe_section(&mut bytes, *b".rdata\0\0", *b".payload"),
        "the host pclntab section must rank below the payload"
    );
    assert!(
        append_pe_rodata(&mut bytes, &payload_bytes),
        "the PE host must carry the payload in a .rodata section"
    );
    let image: GoImage<'_> = GoImage::parse(&bytes).expect("the patched host remains a PE");
    assert!(
        !image
            .symbol_addrs()
            .iter()
            .any(|(name, _, _): &(String, u64, u64)| name == "runtime.pclntab"),
        "the host must carry no runtime.pclntab symbol, so only its moduledata can rank its pclntab"
    );
    let payload_va: u64 = image
        .section_by_name(&[".rodata"])
        .and_then(|section: &disrobe_pass_go::Section<'_>| {
            u64::try_from(payload_pclntab)
                .ok()
                .and_then(|offset: u64| section.address.checked_add(offset))
        })
        .expect("the payload pclntab has a virtual address");
    assert!(
        patch_payload_reference(&mut bytes, payload_va),
        "the PE host must contain a writable data reference slot"
    );
    let analysis: GoAnalysis = analyze(&bytes).expect("the host parses as Go");
    let names: BTreeSet<String> = common::recovered_function_names(&analysis);
    assert!(
        names.contains("main.hostMarker"),
        "the host's own functions must be recovered"
    );
    assert!(
        !names.contains("main.payloadMarker"),
        "the embedded payload's pclntab was reported instead of the host's"
    );
}
