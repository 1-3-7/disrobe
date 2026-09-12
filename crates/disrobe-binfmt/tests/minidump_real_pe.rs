#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use object::{Object as _, ObjectSection as _};

use disrobe_binfmt::containers::{
    CarvedModule, MinidumpFile, MinidumpModule, carve_module, detect_minidump, parse_minidump,
};

#[cfg(windows)]
fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(windows)]
fn image_size_and_headers(pe: &[u8]) -> (u32, u32) {
    let pe_off: usize = disrobe_binfmt::locate_pe_header(pe).expect("pe header");
    let opt: usize = pe_off + 4 + 20;
    (u32_le(pe, opt + 56), u32_le(pe, opt + 60))
}

#[cfg(windows)]
fn map_on_disk_pe(on_disk: &[u8]) -> (u64, u32, Vec<u8>) {
    let file: object::read::File<'_> = object::read::File::parse(on_disk).expect("parse pe");
    assert!(matches!(file.format(), object::BinaryFormat::Pe));
    let image_base: u64 = file.relative_address_base();
    let (size_of_image, size_of_headers): (u32, u32) = image_size_and_headers(on_disk);
    let mut image: Vec<u8> = vec![0u8; size_of_image as usize];
    let header_len: usize = (size_of_headers as usize)
        .min(on_disk.len())
        .min(image.len());
    image[..header_len].copy_from_slice(&on_disk[..header_len]);
    for section in file.sections() {
        let rva: usize = (section.address() - image_base) as usize;
        let Some((file_off, file_size)) = section.file_range() else {
            continue;
        };
        let virtual_size: usize = section.size() as usize;
        let take: usize = (file_size as usize)
            .min(virtual_size)
            .min(on_disk.len().saturating_sub(file_off as usize));
        if rva + take <= image.len() {
            image[rva..rva + take]
                .copy_from_slice(&on_disk[file_off as usize..file_off as usize + take]);
        }
    }
    (image_base, size_of_image, image)
}

#[cfg(windows)]
fn minidump_string(name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&((units.len() * 2) as u32).to_le_bytes());
    for unit in &units {
        blob.extend_from_slice(&unit.to_le_bytes());
    }
    blob.extend_from_slice(&[0u8, 0u8]);
    blob
}

#[cfg(windows)]
fn build_dump(
    image_base: u64,
    size_of_image: u32,
    name: &str,
    arch: u16,
    memory: &[u8],
) -> Vec<u8> {
    let mut sysinfo: Vec<u8> = vec![0u8; 56];
    sysinfo[0..2].copy_from_slice(&arch.to_le_bytes());
    let name_blob: Vec<u8> = minidump_string(name);

    let dir_rva: u32 = 32;
    let dir_len: u32 = 3 * 12;
    let mut cursor: u32 = dir_rva + dir_len;
    let sysinfo_rva: u32 = cursor;
    cursor += sysinfo.len() as u32;
    let name_rva: u32 = cursor;
    cursor += name_blob.len() as u32;
    let module_list_rva: u32 = cursor;
    cursor += 4 + 108;
    let mem64_rva: u32 = cursor;
    cursor += 16 + 16;
    let base_rva: u32 = cursor;

    let mut module: Vec<u8> = vec![0u8; 108];
    module[0..8].copy_from_slice(&image_base.to_le_bytes());
    module[8..12].copy_from_slice(&size_of_image.to_le_bytes());
    module[20..24].copy_from_slice(&name_rva.to_le_bytes());
    let mut module_list: Vec<u8> = Vec::new();
    module_list.extend_from_slice(&1u32.to_le_bytes());
    module_list.extend_from_slice(&module);

    let mut mem64: Vec<u8> = Vec::new();
    mem64.extend_from_slice(&1u64.to_le_bytes());
    mem64.extend_from_slice(&u64::from(base_rva).to_le_bytes());
    mem64.extend_from_slice(&image_base.to_le_bytes());
    mem64.extend_from_slice(&(memory.len() as u64).to_le_bytes());

    let total: usize = base_rva as usize + memory.len();
    let mut buf: Vec<u8> = vec![0u8; total];
    buf[0..4].copy_from_slice(&0x504D_444Du32.to_le_bytes());
    buf[4..8].copy_from_slice(&42899u32.to_le_bytes());
    buf[8..12].copy_from_slice(&3u32.to_le_bytes());
    buf[12..16].copy_from_slice(&dir_rva.to_le_bytes());
    let dir: usize = dir_rva as usize;
    put_dir(&mut buf, dir, 7, sysinfo.len() as u32, sysinfo_rva);
    put_dir(
        &mut buf,
        dir + 12,
        4,
        module_list.len() as u32,
        module_list_rva,
    );
    put_dir(&mut buf, dir + 24, 9, mem64.len() as u32, mem64_rva);
    buf[sysinfo_rva as usize..sysinfo_rva as usize + sysinfo.len()].copy_from_slice(&sysinfo);
    buf[name_rva as usize..name_rva as usize + name_blob.len()].copy_from_slice(&name_blob);
    buf[module_list_rva as usize..module_list_rva as usize + module_list.len()]
        .copy_from_slice(&module_list);
    buf[mem64_rva as usize..mem64_rva as usize + mem64.len()].copy_from_slice(&mem64);
    buf[base_rva as usize..base_rva as usize + memory.len()].copy_from_slice(memory);
    buf
}

#[cfg(windows)]
fn put_dir(buf: &mut [u8], at: usize, stream_type: u32, data_size: u32, rva: u32) {
    buf[at..at + 4].copy_from_slice(&stream_type.to_le_bytes());
    buf[at + 4..at + 8].copy_from_slice(&data_size.to_le_bytes());
    buf[at + 8..at + 12].copy_from_slice(&rva.to_le_bytes());
}

fn compare_text(carved: &CarvedModule, on_disk: &[u8]) -> Option<(usize, usize)> {
    let file: object::read::File<'_> = object::read::File::parse(on_disk).ok()?;
    let base: u64 = file.relative_address_base();
    for section in file.sections() {
        if section.name().unwrap_or_default() == ".text" {
            let rva: usize = (section.address() - base) as usize;
            let (file_off, file_size): (u64, u64) = section.file_range()?;
            let take: usize = (file_size as usize).min(section.size() as usize);
            let disk_text: &[u8] = on_disk.get(file_off as usize..file_off as usize + take)?;
            let carved_text: &[u8] = carved.image.get(rva..rva + take)?;
            let matching: usize = disk_text
                .iter()
                .zip(carved_text)
                .filter(|(a, b): &(&u8, &u8)| a == b)
                .count();
            return Some((matching, take));
        }
    }
    None
}

#[cfg(windows)]
#[test]
fn carves_current_exe_as_real_pe() {
    let exe_path: std::path::PathBuf = std::env::current_exe().expect("current exe");
    let on_disk: Vec<u8> = std::fs::read(&exe_path).expect("read exe");
    let arch: u16 = if cfg!(target_pointer_width = "64") {
        9
    } else {
        0
    };

    let (image_base, size_of_image, mapped): (u64, u32, Vec<u8>) = map_on_disk_pe(&on_disk);
    let name: String = exe_path
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("test.exe")
        .to_owned();
    let dump: Vec<u8> = build_dump(image_base, size_of_image, &name, arch, &mapped);
    assert!(detect_minidump(&dump));

    let file: MinidumpFile = parse_minidump(&dump).expect("parse");
    assert_eq!(file.modules.len(), 1);
    let module: &MinidumpModule = &file.modules[0];
    assert_eq!(module.base_of_image, image_base);

    let carved: CarvedModule = carve_module(&file, &dump, module, 1 << 31).expect("carve");
    assert!(carved.coverage.headers_present);
    assert!(carved.coverage.complete);
    let report = carved.pe_emit.as_ref().expect("pe emit");
    assert!(
        report.structurally_valid,
        "object must validate the emitted image of a real compiled PE"
    );
    assert!(report.sections_rewritten >= 1);

    let (matching, total): (usize, usize) =
        compare_text(&carved, &on_disk).expect("real exe must have a .text section");
    assert_eq!(
        matching, total,
        ".text of the carved real PE must byte-match the on-disk section"
    );
}

#[cfg(windows)]
#[test]
fn extract_to_emits_carved_module_and_summary() {
    use disrobe_binfmt::ContainerKind;

    let exe_path: std::path::PathBuf = std::env::current_exe().expect("current exe");
    let on_disk: Vec<u8> = std::fs::read(&exe_path).expect("read exe");
    let arch: u16 = if cfg!(target_pointer_width = "64") {
        9
    } else {
        0
    };
    let (image_base, size_of_image, mapped): (u64, u32, Vec<u8>) = map_on_disk_pe(&on_disk);
    let name: String = exe_path
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("test.exe")
        .to_owned();
    let dump: Vec<u8> = build_dump(image_base, size_of_image, &name, arch, &mapped);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-minidump-e2e")
            .expect("create scratch dir");
    let out_dir: std::path::PathBuf = scratch.path().to_path_buf();
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(ContainerKind::Minidump, &dump, &out_dir).expect("extract");
    assert_eq!(result.kind, ContainerKind::Minidump);

    let summary: Vec<u8> =
        std::fs::read(out_dir.join(".disrobe-minidump.json")).expect("summary json");
    let summary_text: String = String::from_utf8_lossy(&summary).into_owned();
    assert!(summary_text.contains("coverage_ratio"));
    assert!(summary_text.contains(&name));

    let emitted: Vec<u8> = std::fs::read(out_dir.join(&name)).expect("emitted module image");
    let parsed: object::read::File<'_> =
        object::read::File::parse(&emitted[..]).expect("emitted image parses as an object");
    assert!(matches!(parsed.format(), object::BinaryFormat::Pe));
}

#[test]
#[ignore = "requires DISROBE_MINIDUMP pointing at a real dbghelp .dmp; run manually"]
fn real_dbghelp_dump_oracle() {
    let Ok(dump_path): Result<String, std::env::VarError> = std::env::var("DISROBE_MINIDUMP")
    else {
        eprintln!("set DISROBE_MINIDUMP to a real .dmp path");
        return;
    };
    let dump: Vec<u8> = std::fs::read(&dump_path).expect("read dump");
    assert!(
        detect_minidump(&dump),
        "input must be detected as a minidump"
    );
    let file: MinidumpFile = parse_minidump(&dump).expect("parse real dump");
    eprintln!(
        "real dump: arch={:?} pointer_width={} modules={} memory_regions={}",
        file.arch,
        file.pointer_width,
        file.modules.len(),
        file.memory_regions.len()
    );
    assert!(!file.modules.is_empty(), "real dump must list modules");

    let target: String =
        std::env::var("DISROBE_MINIDUMP_MODULE").unwrap_or_else(|_| "ntdll.dll".to_owned());
    let module: &MinidumpModule = file
        .modules
        .iter()
        .find(|m: &&MinidumpModule| m.file_name().eq_ignore_ascii_case(&target))
        .unwrap_or_else(|| panic!("module {target} not present in dump"));
    eprintln!(
        "carving {} base=0x{:x} size=0x{:x} path={}",
        module.file_name(),
        module.base_of_image,
        module.size_of_image,
        module.name
    );
    let carved: CarvedModule = carve_module(&file, &dump, module, 1u64 << 31).expect("carve");
    eprintln!(
        "coverage: complete={} ratio={:.4} covered={} truncated={} absent_ranges={} headers_present={}",
        carved.coverage.complete,
        carved.coverage.coverage_ratio,
        carved.coverage.covered_bytes,
        carved.coverage.truncated_bytes,
        carved.absent_ranges.len(),
        carved.coverage.headers_present,
    );
    if let Some(report) = &carved.pe_emit {
        eprintln!(
            "pe_emit: valid={} pe32_plus={} sections_rewritten={} import_dlls={:?}",
            report.structurally_valid,
            report.is_pe32_plus,
            report.sections_rewritten,
            report.import_dll_count,
        );
    }

    let on_disk_path: String =
        std::env::var("DISROBE_MINIDUMP_ONDISK").unwrap_or_else(|_| module.name.clone());
    let on_disk: Vec<u8> = std::fs::read(&on_disk_path).expect("read on-disk module");
    let (matching, total): (usize, usize) =
        compare_text(&carved, &on_disk).expect("on-disk module has a .text section");
    let ratio: f64 = matching as f64 / total as f64;
    eprintln!(
        ".text comparison vs on-disk file: {matching}/{total} bytes match ({:.4}%)",
        100.0 * ratio
    );
    assert_eq!(
        matching, total,
        "carved .text must byte-match the on-disk file's .text (reloc-free x64 code)"
    );
}
