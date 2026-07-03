#![allow(dead_code, unreachable_pub)]
use std::io::{Cursor, Write};

use disrobe_pass_swift_objc::macho::{
    FAT_MAGIC_BE, LC_ENCRYPTION_INFO_64, LC_SEGMENT_64, MH_MAGIC_64,
};

pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;
pub const MH_EXECUTE: u32 = 0x2;

pub struct MachoSliceBuilder {
    pub segments: Vec<MachoSegmentSpec>,
    pub encryption_id: u32,
}

#[derive(Debug, Clone)]
pub struct MachoSegmentSpec {
    pub seg_name: &'static str,
    pub sections: Vec<MachoSectionSpec>,
}

#[derive(Debug, Clone)]
pub struct MachoSectionSpec {
    pub sect_name: &'static str,
    pub seg_name: &'static str,
    pub data: Vec<u8>,
}

#[must_use]
pub fn build_macho64_slice(builder: &MachoSliceBuilder) -> Vec<u8> {
    let header_size: usize = 32;
    let mut segment_cmd_sizes: Vec<usize> = Vec::with_capacity(builder.segments.len());
    for seg in &builder.segments {
        segment_cmd_sizes.push(72 + seg.sections.len() * 80);
    }
    let encryption_cmd_size: usize = 24;
    let sizeofcmds: usize = segment_cmd_sizes.iter().sum::<usize>() + encryption_cmd_size;

    let mut section_data_offsets: Vec<Vec<usize>> = Vec::with_capacity(builder.segments.len());
    let mut payload_cursor: usize = header_size + sizeofcmds;
    for seg in &builder.segments {
        let mut offsets: Vec<usize> = Vec::with_capacity(seg.sections.len());
        for sec in &seg.sections {
            offsets.push(payload_cursor);
            payload_cursor += sec.data.len();
        }
        section_data_offsets.push(offsets);
    }
    let total_size: usize = payload_cursor;

    let mut out: Vec<u8> = vec![0u8; total_size];
    let mut cursor: Cursor<&mut [u8]> = Cursor::new(&mut out);

    let ncmds: u32 = u32::try_from(builder.segments.len() + 1).expect("ncmds fits");
    let sizeofcmds_u32: u32 = u32::try_from(sizeofcmds).expect("sizeofcmds fits");

    cursor.write_all(&MH_MAGIC_64.to_le_bytes()).expect("magic");
    cursor
        .write_all(&CPU_TYPE_ARM64.to_le_bytes())
        .expect("cputype");
    cursor.write_all(&0u32.to_le_bytes()).expect("cpusubtype");
    cursor
        .write_all(&MH_EXECUTE.to_le_bytes())
        .expect("filetype");
    cursor.write_all(&ncmds.to_le_bytes()).expect("ncmds");
    cursor
        .write_all(&sizeofcmds_u32.to_le_bytes())
        .expect("sizeofcmds");
    cursor.write_all(&0u32.to_le_bytes()).expect("flags");
    cursor.write_all(&0u32.to_le_bytes()).expect("reserved");

    for (seg, (cmdsize, offsets)) in builder
        .segments
        .iter()
        .zip(segment_cmd_sizes.iter().zip(section_data_offsets.iter()))
    {
        let cmdsize_u32: u32 = u32::try_from(*cmdsize).expect("cmdsize fits");
        let nsects: u32 = u32::try_from(seg.sections.len()).expect("nsects fits");
        let payload_bytes: u64 = offsets
            .last()
            .copied()
            .and_then(|last: usize| {
                seg.sections
                    .last()
                    .map(|s: &MachoSectionSpec| (last + s.data.len()) as u64)
            })
            .unwrap_or(0);
        let first_off: u64 = offsets.first().copied().unwrap_or(0) as u64;
        let seg_filesize: u64 = payload_bytes.saturating_sub(first_off);

        cursor.write_all(&LC_SEGMENT_64.to_le_bytes()).expect("lc");
        cursor
            .write_all(&cmdsize_u32.to_le_bytes())
            .expect("cmdsize");
        write_name16(&mut cursor, seg.seg_name);
        cursor.write_all(&0u64.to_le_bytes()).expect("vmaddr");
        cursor
            .write_all(&seg_filesize.to_le_bytes())
            .expect("vmsize");
        cursor.write_all(&first_off.to_le_bytes()).expect("fileoff");
        cursor
            .write_all(&seg_filesize.to_le_bytes())
            .expect("filesize");
        cursor.write_all(&0u32.to_le_bytes()).expect("maxprot");
        cursor.write_all(&0u32.to_le_bytes()).expect("initprot");
        cursor.write_all(&nsects.to_le_bytes()).expect("nsects");
        cursor.write_all(&0u32.to_le_bytes()).expect("flags");

        for (sec, off) in seg.sections.iter().zip(offsets.iter()) {
            let offset_u32: u32 = u32::try_from(*off).expect("offset fits");
            let size_u64: u64 = sec.data.len() as u64;
            write_name16(&mut cursor, sec.sect_name);
            write_name16(&mut cursor, sec.seg_name);
            cursor.write_all(&0u64.to_le_bytes()).expect("addr");
            cursor.write_all(&size_u64.to_le_bytes()).expect("size");
            cursor.write_all(&offset_u32.to_le_bytes()).expect("offset");
            cursor.write_all(&0u32.to_le_bytes()).expect("align");
            cursor.write_all(&0u32.to_le_bytes()).expect("reloff");
            cursor.write_all(&0u32.to_le_bytes()).expect("nreloc");
            cursor.write_all(&0u32.to_le_bytes()).expect("flags");
            cursor.write_all(&0u32.to_le_bytes()).expect("reserved1");
            cursor.write_all(&0u32.to_le_bytes()).expect("reserved2");
            cursor.write_all(&0u32.to_le_bytes()).expect("reserved3");
        }
    }

    cursor
        .write_all(&LC_ENCRYPTION_INFO_64.to_le_bytes())
        .expect("lc");
    cursor.write_all(&24u32.to_le_bytes()).expect("cmdsize");
    cursor.write_all(&0u32.to_le_bytes()).expect("cryptoff");
    cursor.write_all(&0u32.to_le_bytes()).expect("cryptsize");
    cursor
        .write_all(&builder.encryption_id.to_le_bytes())
        .expect("cryptid");
    cursor.write_all(&0u32.to_le_bytes()).expect("pad");

    for (seg, offsets) in builder.segments.iter().zip(section_data_offsets.iter()) {
        for (sec, off) in seg.sections.iter().zip(offsets.iter()) {
            let _ = seg;
            out[*off..*off + sec.data.len()].copy_from_slice(&sec.data);
        }
    }

    out
}

fn write_name16(cursor: &mut Cursor<&mut [u8]>, name: &str) {
    let mut buf: [u8; 16] = [0u8; 16];
    let bytes: &[u8] = name.as_bytes();
    let len: usize = bytes.len().min(16);
    buf[..len].copy_from_slice(&bytes[..len]);
    cursor.write_all(&buf).expect("name16");
}

#[must_use]
pub fn build_fat_macho(slice: &[u8]) -> Vec<u8> {
    let header_size: usize = 8 + 20;
    let slice_offset: usize = header_size;
    let slice_size: u32 = u32::try_from(slice.len()).expect("slice size fits");

    let mut out: Vec<u8> = Vec::with_capacity(slice_offset + slice.len());
    out.extend_from_slice(&FAT_MAGIC_BE.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(u32::try_from(slice_offset).expect("offset fits")).to_be_bytes());
    out.extend_from_slice(&slice_size.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(slice);
    out
}

#[must_use]
pub fn build_swift_reflstr_payload(mangled: &[&str]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for s in mangled {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

#[must_use]
pub fn build_objc_methname_payload(selectors: &[&str]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for s in selectors {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

#[must_use]
pub fn build_objc_classlist_payload(class_pointer_count: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(class_pointer_count * 8);
    for i in 0..class_pointer_count {
        let ptr: u64 = 0x1_0000_0000 + (i as u64) * 0x40;
        out.extend_from_slice(&ptr.to_le_bytes());
    }
    out
}

#[must_use]
pub fn build_entitlements_xml() -> Vec<u8> {
    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>application-identifier</key>
  <string>ABC123.com.example.app</string>
  <key>get-task-allow</key>
  <true/>
  <key>com.apple.developer.team-identifier</key>
  <string>ABC123</string>
  <key>aps-environment</key>
  <string>development</string>
</dict>
</plist>
"#;
    XML.as_bytes().to_vec()
}

#[must_use]
pub fn build_binary_info_plist() -> Vec<u8> {
    use plist::{Dictionary, Value};
    let mut dict: Dictionary = Dictionary::new();
    dict.insert(
        "CFBundleIdentifier".into(),
        Value::String("com.example.app".into()),
    );
    dict.insert("CFBundleName".into(), Value::String("Example".into()));
    dict.insert("CFBundleExecutable".into(), Value::String("Example".into()));
    dict.insert(
        "CFBundleShortVersionString".into(),
        Value::String("1.0.0".into()),
    );
    dict.insert("CFBundleVersion".into(), Value::String("42".into()));
    dict.insert("MinimumOSVersion".into(), Value::String("15.0".into()));
    dict.insert(
        "CFBundleSupportedPlatforms".into(),
        Value::Array(vec![Value::String("iPhoneOS".into())]),
    );
    dict.insert(
        "UIDeviceFamily".into(),
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(2.into())]),
    );
    let value: Value = Value::Dictionary(dict);
    let mut out: Vec<u8> = Vec::new();
    value
        .to_writer_binary(&mut out)
        .expect("write binary plist");
    out
}

#[must_use]
pub fn wrap_in_code_signature_blob(xml: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(xml.len() + 32);
    out.extend_from_slice(b"\x00\x00\x00\x00prefix\x00\x00");
    let magic: u32 = 0xFADE_7171;
    let len: u32 = u32::try_from(xml.len() + 8).expect("blob len fits");
    out.extend_from_slice(&magic.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(xml);
    out
}

#[must_use]
pub fn build_ipa_with_main_binary(
    app_name: &str,
    main_binary: &[u8],
    info_plist: &[u8],
) -> Vec<u8> {
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        let mut writer: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let app_dir: String = format!("Payload/{app_name}.app");
        writer
            .start_file(format!("{app_dir}/{app_name}"), opts)
            .expect("start main");
        writer.write_all(main_binary).expect("write main");
        writer
            .start_file(format!("{app_dir}/Info.plist"), opts)
            .expect("start plist");
        writer.write_all(info_plist).expect("write plist");
        writer.finish().expect("zip finish");
    }
    buf
}
