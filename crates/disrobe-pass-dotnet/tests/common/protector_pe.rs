#![allow(
    dead_code,
    clippy::redundant_pub_crate,
    unreachable_pub,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

const TEXT_RVA: u32 = 0x2000;
const TEXT_RAW_PTR: u32 = 0x200;
const HEADERS_LEN: usize = TEXT_RAW_PTR as usize;
const CLR_OFF: u32 = 0x8;
const KEY_OFF: u32 = 0x80;
const METADATA_OFF: u32 = 0x400;
const STUB_REGION_OFF: u32 = 0x100;

#[derive(Clone)]
struct Stream {
    name: &'static str,
    bytes: Vec<u8>,
}

pub(crate) struct ProtectedMethod {
    pub(crate) rid: u32,
    pub(crate) name_off: u32,
    pub(crate) rva: u32,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn tiny_method_body(code: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(code.len() + 1);
    let header: u8 = u8::try_from(code.len()).unwrap() << 2 | 0x02;
    body.push(header);
    body.extend_from_slice(code);
    body
}

pub(crate) fn ilprotector_invoke_stub(method_id: u32) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    code.push(0x7E);
    code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
    if method_id <= 8 {
        code.push(0x16 + method_id as u8);
    } else {
        code.push(0x20);
        code.extend_from_slice(&method_id.to_le_bytes());
    }
    code.push(0x28);
    code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
    code.push(0x2A);
    tiny_method_body(&code)
}

fn push_compressed_uint(out: &mut Vec<u8>, value: u32) {
    if value < 0x80 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push((0x80 | (value >> 8)) as u8);
        out.push((value & 0xFF) as u8);
    } else {
        out.push((0xC0 | (value >> 24)) as u8);
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    }
}

fn strings_heap(names: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut heap: Vec<u8> = vec![0u8];
    let mut offsets: Vec<u32> = Vec::with_capacity(names.len());
    for n in names {
        offsets.push(u32::try_from(heap.len()).unwrap());
        heap.extend_from_slice(n.as_bytes());
        heap.push(0);
    }
    (heap, offsets)
}

fn blob_heap_byte_array_sig() -> (Vec<u8>, u32) {
    let mut heap: Vec<u8> = vec![0u8];
    let off: u32 = u32::try_from(heap.len()).unwrap();
    let sig: [u8; 3] = [0x06, 0x1D, 0x05];
    push_compressed_uint(&mut heap, sig.len() as u32);
    heap.extend_from_slice(&sig);
    (heap, off)
}

fn build_metadata(streams: &[Stream]) -> Vec<u8> {
    let version: &[u8] = b"v4.0.30319\0";
    let version_padded: usize = version.len().div_ceil(4) * 4;
    let mut header_len: usize = 4 + 2 + 2 + 4 + 4 + version_padded + 2 + 2;
    for st in streams {
        header_len += 8;
        let name_len: usize = st.name.len() + 1;
        header_len += name_len.div_ceil(4) * 4;
    }
    let mut md: Vec<u8> = Vec::new();
    md.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&0u32.to_le_bytes());
    md.extend_from_slice(&u32::try_from(version_padded).unwrap().to_le_bytes());
    md.extend_from_slice(version);
    md.resize(4 + 2 + 2 + 4 + 4 + version_padded, 0);
    md.extend_from_slice(&0u16.to_le_bytes());
    md.extend_from_slice(&u16::try_from(streams.len()).unwrap().to_le_bytes());

    let mut data_off: usize = header_len;
    let mut data: Vec<u8> = Vec::new();
    for st in streams {
        md.extend_from_slice(&u32::try_from(data_off).unwrap().to_le_bytes());
        md.extend_from_slice(&u32::try_from(st.bytes.len()).unwrap().to_le_bytes());
        let mut name_bytes: Vec<u8> = st.name.as_bytes().to_vec();
        name_bytes.push(0);
        while !name_bytes.len().is_multiple_of(4) {
            name_bytes.push(0);
        }
        md.extend_from_slice(&name_bytes);
        data.extend_from_slice(&st.bytes);
        data_off += st.bytes.len();
    }
    assert_eq!(md.len(), header_len);
    md.extend_from_slice(&data);
    md
}

pub(crate) struct IlpLayout<'a> {
    pub(crate) stubs: &'a [ProtectedMethod],
    pub(crate) module_name_off: u32,
    pub(crate) type_name_off: u32,
    pub(crate) delegate_field_name_off: u32,
    pub(crate) delegate_field_sig_off: u32,
    pub(crate) key_field_name_off: Option<u32>,
    pub(crate) key_field_sig_off: u32,
    pub(crate) key_field_rva: Option<u32>,
    pub(crate) resource_name_off: u32,
    pub(crate) resource_offset: u32,
}

fn ilp_table_stream(layout: &IlpLayout<'_>) -> Vec<u8> {
    let field_count: u32 = 1 + u32::from(layout.key_field_name_off.is_some());
    let method_count: u32 = u32::try_from(layout.stubs.len()).unwrap();
    let fieldrva_count: u32 = u32::from(layout.key_field_rva.is_some());

    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(&0u32.to_le_bytes());
    s.push(2);
    s.push(0);
    s.push(0);
    s.push(0);
    let mut valid: u64 =
        (1u64 << 0x00) | (1u64 << 0x02) | (1u64 << 0x04) | (1u64 << 0x06) | (1u64 << 0x28);
    if fieldrva_count > 0 {
        valid |= 1u64 << 0x1D;
    }
    s.extend_from_slice(&valid.to_le_bytes());
    s.extend_from_slice(&0u64.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&field_count.to_le_bytes());
    s.extend_from_slice(&method_count.to_le_bytes());
    if fieldrva_count > 0 {
        s.extend_from_slice(&fieldrva_count.to_le_bytes());
    }
    s.extend_from_slice(&1u32.to_le_bytes());

    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&(layout.module_name_off as u16).to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());

    s.extend_from_slice(&0x0010_0001u32.to_le_bytes());
    s.extend_from_slice(&(layout.type_name_off as u16).to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());

    s.extend_from_slice(&0x0008u16.to_le_bytes());
    s.extend_from_slice(&(layout.delegate_field_name_off as u16).to_le_bytes());
    s.extend_from_slice(&(layout.delegate_field_sig_off as u16).to_le_bytes());
    if let Some(key_name) = layout.key_field_name_off {
        s.extend_from_slice(&0x0008u16.to_le_bytes());
        s.extend_from_slice(&(key_name as u16).to_le_bytes());
        s.extend_from_slice(&(layout.key_field_sig_off as u16).to_le_bytes());
    }

    for stub in layout.stubs {
        s.extend_from_slice(&stub.rva.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&0x0016u16.to_le_bytes());
        s.extend_from_slice(&(stub.name_off as u16).to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
    }

    if let Some(rva) = layout.key_field_rva {
        s.extend_from_slice(&rva.to_le_bytes());
        s.extend_from_slice(&2u16.to_le_bytes());
    }

    s.extend_from_slice(&layout.resource_offset.to_le_bytes());
    s.extend_from_slice(&0u32.to_le_bytes());
    s.extend_from_slice(&(layout.resource_name_off as u16).to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s
}

pub(crate) fn build_ilprotector_pe(
    method_ids: &[u32],
    resource_payload: &[u8],
    key: Option<&[u8]>,
) -> Vec<u8> {
    let (strings, offs): (Vec<u8>, Vec<u32>) = strings_heap(&[
        "Ilp.Module",
        "Protected",
        "Invoke",
        "ILProtectorKey",
        "Protect",
        "Protect32.dll",
        "ILProtector",
    ]);
    let module_name_off: u32 = offs[0];
    let type_name_off: u32 = offs[1];
    let delegate_field_name_off: u32 = offs[2];
    let key_field_name_off: u32 = offs[3];
    let resource_name_off: u32 = offs[4];

    let (blob, byte_array_sig_off): (Vec<u8>, u32) = blob_heap_byte_array_sig();

    let stub_region_base: u32 = TEXT_RVA + STUB_REGION_OFF;
    let mut stubs: Vec<ProtectedMethod> = Vec::with_capacity(method_ids.len());
    let mut stub_cursor: u32 = stub_region_base;
    for (i, id) in method_ids.iter().enumerate() {
        let body: Vec<u8> = ilprotector_invoke_stub(*id);
        stubs.push(ProtectedMethod {
            rid: u32::try_from(i).unwrap() + 1,
            name_off: delegate_field_name_off,
            rva: stub_cursor,
            body,
        });
        stub_cursor += 0x40;
    }

    let key_field_rva: Option<u32> = key.map(|_| TEXT_RVA + KEY_OFF);

    let layout: IlpLayout<'_> = IlpLayout {
        stubs: &stubs,
        module_name_off,
        type_name_off,
        delegate_field_name_off,
        delegate_field_sig_off: byte_array_sig_off,
        key_field_name_off: key.map(|_| key_field_name_off),
        key_field_sig_off: byte_array_sig_off,
        key_field_rva,
        resource_name_off,
        resource_offset: 0,
    };
    let tables: Vec<u8> = ilp_table_stream(&layout);
    let guid: Vec<u8> = vec![0u8; 16];
    let streams: Vec<Stream> = vec![
        Stream {
            name: "#~",
            bytes: tables,
        },
        Stream {
            name: "#Strings",
            bytes: strings,
        },
        Stream {
            name: "#GUID",
            bytes: guid,
        },
        Stream {
            name: "#Blob",
            bytes: blob,
        },
    ];
    let metadata: Vec<u8> = build_metadata(&streams);

    let resources_off: u32 = METADATA_OFF + u32::try_from(metadata.len()).unwrap();
    let resources_off: u32 = (resources_off + 3) & !3;
    let resources_rva: u32 = TEXT_RVA + resources_off;

    let mut resource_entry: Vec<u8> = Vec::new();
    resource_entry.extend_from_slice(&u32::try_from(resource_payload.len()).unwrap().to_le_bytes());
    resource_entry.extend_from_slice(resource_payload);

    let text_len: usize =
        (resources_off as usize + resource_entry.len() + 0x10).next_multiple_of(0x200);
    let mut text: Vec<u8> = vec![0u8; text_len];

    for stub in &stubs {
        let off: usize = (stub.rva - TEXT_RVA) as usize;
        text[off..off + stub.body.len()].copy_from_slice(&stub.body);
    }
    if let Some(key_bytes) = key {
        let off: usize = KEY_OFF as usize;
        text[off..off + key_bytes.len()].copy_from_slice(key_bytes);
    }
    let md_start: usize = METADATA_OFF as usize;
    text[md_start..md_start + metadata.len()].copy_from_slice(&metadata);
    let res_start: usize = resources_off as usize;
    text[res_start..res_start + resource_entry.len()].copy_from_slice(&resource_entry);

    let clr: Vec<u8> = clr_header(
        TEXT_RVA + METADATA_OFF,
        u32::try_from(metadata.len()).unwrap(),
        resources_rva,
        u32::try_from(resource_entry.len()).unwrap(),
    );
    let clr_start: usize = CLR_OFF as usize;
    text[clr_start..clr_start + clr.len()].copy_from_slice(&clr);

    assemble_pe(&[(b".text\0\0\0", &text, 0x6000_0020)], TEXT_RVA + CLR_OFF)
}

pub(crate) struct MtcLayout<'a> {
    pub(crate) protected: &'a [ProtectedMethod],
    pub(crate) plain_methods: &'a [ProtectedMethod],
    pub(crate) module_name_off: u32,
    pub(crate) type_name_off: u32,
    pub(crate) key_field_name_off: Option<u32>,
    pub(crate) key_field_sig_off: u32,
    pub(crate) key_field_rva: Option<u32>,
}

fn mtc_table_stream(layout: &MtcLayout<'_>) -> Vec<u8> {
    let field_count: u32 = u32::from(layout.key_field_name_off.is_some());
    let method_count: u32 =
        u32::try_from(layout.protected.len() + layout.plain_methods.len()).unwrap();
    let fieldrva_count: u32 = u32::from(layout.key_field_rva.is_some());

    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(&0u32.to_le_bytes());
    s.push(2);
    s.push(0);
    s.push(0);
    s.push(0);
    let mut valid: u64 = (1u64 << 0x00) | (1u64 << 0x02) | (1u64 << 0x06);
    if field_count > 0 {
        valid |= 1u64 << 0x04;
    }
    if fieldrva_count > 0 {
        valid |= 1u64 << 0x1D;
    }
    s.extend_from_slice(&valid.to_le_bytes());
    s.extend_from_slice(&0u64.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    if field_count > 0 {
        s.extend_from_slice(&field_count.to_le_bytes());
    }
    s.extend_from_slice(&method_count.to_le_bytes());
    if fieldrva_count > 0 {
        s.extend_from_slice(&fieldrva_count.to_le_bytes());
    }

    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&(layout.module_name_off as u16).to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());

    s.extend_from_slice(&0x0010_0001u32.to_le_bytes());
    s.extend_from_slice(&(layout.type_name_off as u16).to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());

    if let Some(key_name) = layout.key_field_name_off {
        s.extend_from_slice(&0x0008u16.to_le_bytes());
        s.extend_from_slice(&(key_name as u16).to_le_bytes());
        s.extend_from_slice(&(layout.key_field_sig_off as u16).to_le_bytes());
    }

    for m in layout.protected {
        s.extend_from_slice(&m.rva.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&0x0016u16.to_le_bytes());
        s.extend_from_slice(&(m.name_off as u16).to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
    }
    for m in layout.plain_methods {
        s.extend_from_slice(&m.rva.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&0x0016u16.to_le_bytes());
        s.extend_from_slice(&(m.name_off as u16).to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
    }

    if let Some(rva) = layout.key_field_rva {
        s.extend_from_slice(&rva.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
    }
    s
}

pub(crate) fn build_maxtocode_pe(
    protected_count: u32,
    plain_method: &[u8],
    encrypted_section: &[u8],
    key: Option<&[u8]>,
) -> Vec<u8> {
    const MTC_RVA: u32 = 0x4000;
    const MTC_RAW: u32 = 0x400;

    let (strings, offs): (Vec<u8>, Vec<u32>) = strings_heap(&[
        "Mtc.Module",
        "Protected",
        "Invoke",
        "MaxToCodeKey",
        "MaxtoCode",
        "NetSafe",
    ]);
    let module_name_off: u32 = offs[0];
    let type_name_off: u32 = offs[1];
    let method_name_off: u32 = offs[2];
    let key_field_name_off: u32 = offs[3];

    let (blob, byte_array_sig_off): (Vec<u8>, u32) = blob_heap_byte_array_sig();

    let protected: Vec<ProtectedMethod> = (0..protected_count)
        .map(|_| ProtectedMethod {
            rid: 0,
            name_off: method_name_off,
            rva: 0,
            body: Vec::new(),
        })
        .collect();
    let plain_rva: u32 = TEXT_RVA + STUB_REGION_OFF;
    let plain_methods: Vec<ProtectedMethod> = vec![ProtectedMethod {
        rid: 0,
        name_off: method_name_off,
        rva: plain_rva,
        body: plain_method.to_vec(),
    }];

    let key_field_rva: Option<u32> = key.map(|_| TEXT_RVA + KEY_OFF);
    let layout: MtcLayout<'_> = MtcLayout {
        protected: &protected,
        plain_methods: &plain_methods,
        module_name_off,
        type_name_off,
        key_field_name_off: key.map(|_| key_field_name_off),
        key_field_sig_off: byte_array_sig_off,
        key_field_rva,
    };
    let tables: Vec<u8> = mtc_table_stream(&layout);
    let guid: Vec<u8> = vec![0u8; 16];
    let streams: Vec<Stream> = vec![
        Stream {
            name: "#~",
            bytes: tables,
        },
        Stream {
            name: "#Strings",
            bytes: strings,
        },
        Stream {
            name: "#GUID",
            bytes: guid,
        },
        Stream {
            name: "#Blob",
            bytes: blob,
        },
    ];
    let metadata: Vec<u8> = build_metadata(&streams);

    let text_len: usize = (METADATA_OFF as usize + metadata.len() + 0x10).next_multiple_of(0x200);
    let mut text: Vec<u8> = vec![0u8; text_len];

    let plain_off: usize = STUB_REGION_OFF as usize;
    text[plain_off..plain_off + plain_method.len()].copy_from_slice(plain_method);
    if let Some(key_bytes) = key {
        let off: usize = KEY_OFF as usize;
        text[off..off + key_bytes.len()].copy_from_slice(key_bytes);
    }
    let md_start: usize = METADATA_OFF as usize;
    text[md_start..md_start + metadata.len()].copy_from_slice(&metadata);

    let clr: Vec<u8> = clr_header(
        TEXT_RVA + METADATA_OFF,
        u32::try_from(metadata.len()).unwrap(),
        0,
        0,
    );
    let clr_start: usize = CLR_OFF as usize;
    text[clr_start..clr_start + clr.len()].copy_from_slice(&clr);

    let mut mtc: Vec<u8> = vec![0u8; MTC_RAW as usize];
    assert!(encrypted_section.len() <= mtc.len());
    mtc[..encrypted_section.len()].copy_from_slice(encrypted_section);

    let _ = (MTC_RVA, MTC_RAW);
    assemble_pe(
        &[
            (b".text\0\0\0", &text, 0x6000_0020),
            (b".mtc\0\0\0\0", &mtc, 0x4000_0040),
        ],
        TEXT_RVA + CLR_OFF,
    )
}

fn clr_header(
    metadata_rva: u32,
    metadata_size: u32,
    resources_rva: u32,
    resources_size: u32,
) -> Vec<u8> {
    let mut clr: Vec<u8> = Vec::new();
    clr.extend_from_slice(&72u32.to_le_bytes());
    clr.extend_from_slice(&2u16.to_le_bytes());
    clr.extend_from_slice(&5u16.to_le_bytes());
    clr.extend_from_slice(&metadata_rva.to_le_bytes());
    clr.extend_from_slice(&metadata_size.to_le_bytes());
    clr.extend_from_slice(&1u32.to_le_bytes());
    clr.extend_from_slice(&0u32.to_le_bytes());
    clr.extend_from_slice(&resources_rva.to_le_bytes());
    clr.extend_from_slice(&resources_size.to_le_bytes());
    while clr.len() < 72 {
        clr.push(0);
    }
    clr
}

pub(crate) struct FieldBlob {
    pub(crate) name: &'static str,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct DotnetPeSpec {
    pub(crate) watermarks: Vec<&'static str>,
    pub(crate) cctor_body: Option<Vec<u8>>,
    pub(crate) decryptor_body: Option<Vec<u8>>,
    pub(crate) us_entries: Vec<Vec<u16>>,
    pub(crate) field_blobs: Vec<FieldBlob>,
    pub(crate) resource: Option<(&'static str, Vec<u8>)>,
}

impl DotnetPeSpec {
    pub(crate) fn new(watermarks: &[&'static str]) -> Self {
        Self {
            watermarks: watermarks.to_vec(),
            cctor_body: None,
            decryptor_body: None,
            us_entries: Vec::new(),
            field_blobs: Vec::new(),
            resource: None,
        }
    }
}

pub(crate) fn ldc_i4_store_cctor(key: u32, field_token: u32) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    code.push(0x20);
    code.extend_from_slice(&key.to_le_bytes());
    code.push(0x80);
    code.extend_from_slice(&field_token.to_le_bytes());
    code.push(0x2A);
    tiny_method_body(&code)
}

fn build_us_heap(entries: &[Vec<u16>]) -> Vec<u8> {
    let mut heap: Vec<u8> = vec![0u8];
    for units in entries {
        let blob_len: u32 = u32::try_from(units.len() * 2 + 1).unwrap();
        push_compressed_uint(&mut heap, blob_len);
        for &u in units {
            heap.extend_from_slice(&u.to_le_bytes());
        }
        heap.push(0);
    }
    heap
}

fn dotnet_table_stream(
    string_count: u32,
    blob_count: u32,
    field_count: u32,
    method_count: u32,
    fieldrva_rows: &[(u32, u32)],
    resource_row: Option<(u32, u32)>,
    module_name_off: u32,
    type_name_off: u32,
    field_rows: &[(u32, u32)],
    method_rows: &[(u32, u32, u32, u16)],
) -> Vec<u8> {
    let wide_str: bool = string_count >= (1 << 16);
    let wide_blob: bool = blob_count >= (1 << 16);
    let _ = (field_count, method_count);

    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(&0u32.to_le_bytes());
    s.push(2);
    s.push(0);
    let heap_sizes: u8 = u8::from(wide_str) | (u8::from(wide_blob) << 2);
    s.push(heap_sizes);
    s.push(0);

    let mut valid: u64 = (1u64 << 0x00) | (1u64 << 0x02);
    if !field_rows.is_empty() {
        valid |= 1u64 << 0x04;
    }
    if !method_rows.is_empty() {
        valid |= 1u64 << 0x06;
    }
    if !fieldrva_rows.is_empty() {
        valid |= 1u64 << 0x1D;
    }
    if resource_row.is_some() {
        valid |= 1u64 << 0x28;
    }
    s.extend_from_slice(&valid.to_le_bytes());
    s.extend_from_slice(&0u64.to_le_bytes());

    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    if !field_rows.is_empty() {
        s.extend_from_slice(&u32::try_from(field_rows.len()).unwrap().to_le_bytes());
    }
    if !method_rows.is_empty() {
        s.extend_from_slice(&u32::try_from(method_rows.len()).unwrap().to_le_bytes());
    }
    if !fieldrva_rows.is_empty() {
        s.extend_from_slice(&u32::try_from(fieldrva_rows.len()).unwrap().to_le_bytes());
    }
    if resource_row.is_some() {
        s.extend_from_slice(&1u32.to_le_bytes());
    }

    let emit_str = |s: &mut Vec<u8>, off: u32| {
        if wide_str {
            s.extend_from_slice(&off.to_le_bytes());
        } else {
            s.extend_from_slice(&(off as u16).to_le_bytes());
        }
    };
    let emit_blob = |s: &mut Vec<u8>, off: u32| {
        if wide_blob {
            s.extend_from_slice(&off.to_le_bytes());
        } else {
            s.extend_from_slice(&(off as u16).to_le_bytes());
        }
    };

    s.extend_from_slice(&0u16.to_le_bytes());
    emit_str(&mut s, module_name_off);
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());

    s.extend_from_slice(&0x0010_0001u32.to_le_bytes());
    emit_str(&mut s, type_name_off);
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());

    for (name_off, sig_off) in field_rows {
        s.extend_from_slice(&0x0016u16.to_le_bytes());
        emit_str(&mut s, *name_off);
        emit_blob(&mut s, *sig_off);
    }

    for (rva, name_off, sig_off, flags) in method_rows {
        s.extend_from_slice(&rva.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&flags.to_le_bytes());
        emit_str(&mut s, *name_off);
        emit_blob(&mut s, *sig_off);
        s.extend_from_slice(&1u16.to_le_bytes());
    }

    for (rva, field_rid) in fieldrva_rows {
        s.extend_from_slice(&rva.to_le_bytes());
        s.extend_from_slice(&(*field_rid as u16).to_le_bytes());
    }

    if let Some((offset, name_off)) = resource_row {
        s.extend_from_slice(&offset.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        emit_str(&mut s, name_off);
        s.extend_from_slice(&0u16.to_le_bytes());
    }
    s
}

pub(crate) fn build_dotnet_pe(spec: &DotnetPeSpec) -> Vec<u8> {
    const CCTOR_OFF: u32 = 0x100;
    const DECRYPTOR_OFF: u32 = 0x140;
    const FIELDRVA_BASE: u32 = 0x180;

    let mut names: Vec<&str> = vec!["Prot.Module", "Protected", ".cctor", "Decrypt"];
    let mut field_name_indices: Vec<usize> = Vec::with_capacity(spec.field_blobs.len());
    for fb in &spec.field_blobs {
        field_name_indices.push(names.len());
        names.push(fb.name);
    }
    let resource_name_idx: Option<usize> =
        spec.resource
            .as_ref()
            .map(|(n, _): &(&'static str, Vec<u8>)| {
                names.push(n);
                names.len() - 1
            });
    for w in &spec.watermarks {
        names.push(w);
    }
    let (strings, offs): (Vec<u8>, Vec<u32>) = strings_heap(&names);
    let module_name_off: u32 = offs[0];
    let type_name_off: u32 = offs[1];
    let cctor_name_off: u32 = offs[2];
    let decrypt_name_off: u32 = offs[3];

    let mut blob: Vec<u8> = vec![0u8];
    let int32_sig_off: u32 = u32::try_from(blob.len()).unwrap();
    let int32_sig: [u8; 2] = [0x06, 0x08];
    push_compressed_uint(&mut blob, int32_sig.len() as u32);
    blob.extend_from_slice(&int32_sig);
    let byte_array_sig_off: u32 = u32::try_from(blob.len()).unwrap();
    let byte_array_sig: [u8; 3] = [0x06, 0x1D, 0x05];
    push_compressed_uint(&mut blob, byte_array_sig.len() as u32);
    blob.extend_from_slice(&byte_array_sig);
    let static_void_sig_off: u32 = u32::try_from(blob.len()).unwrap();
    let static_void_sig: [u8; 3] = [0x00, 0x00, 0x01];
    push_compressed_uint(&mut blob, static_void_sig.len() as u32);
    blob.extend_from_slice(&static_void_sig);

    let mut field_rows: Vec<(u32, u32)> = Vec::new();
    let mut fieldrva_rows: Vec<(u32, u32)> = Vec::new();
    let mut field_data: Vec<(u32, Vec<u8>)> = Vec::new();
    field_rows.push((type_name_off, int32_sig_off));
    let mut next_rva: u32 = TEXT_RVA + FIELDRVA_BASE;
    for (i, fb) in spec.field_blobs.iter().enumerate() {
        let field_rid: u32 = u32::try_from(field_rows.len() + 1).unwrap();
        field_rows.push((offs[field_name_indices[i]], byte_array_sig_off));
        fieldrva_rows.push((next_rva, field_rid));
        field_data.push((next_rva, fb.bytes.clone()));
        next_rva += u32::try_from(fb.bytes.len())
            .unwrap()
            .next_multiple_of(8)
            .max(8);
    }

    let mut method_rows: Vec<(u32, u32, u32, u16)> = Vec::new();
    if spec.cctor_body.is_some() {
        method_rows.push((
            TEXT_RVA + CCTOR_OFF,
            cctor_name_off,
            static_void_sig_off,
            0x0016,
        ));
    }
    if spec.decryptor_body.is_some() {
        method_rows.push((
            TEXT_RVA + DECRYPTOR_OFF,
            decrypt_name_off,
            byte_array_sig_off,
            0x0016,
        ));
    }

    let us_heap: Vec<u8> = build_us_heap(&spec.us_entries);

    let mut resource_entry: Vec<u8> = Vec::new();
    let resource_row: Option<(u32, u32)> = if let Some((_, payload)) = &spec.resource {
        resource_entry.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        resource_entry.extend_from_slice(payload);
        let name_idx: usize = resource_name_idx.unwrap();
        Some((0u32, offs[name_idx]))
    } else {
        None
    };

    let tables: Vec<u8> = dotnet_table_stream(
        u32::try_from(strings.len()).unwrap(),
        u32::try_from(blob.len()).unwrap(),
        u32::try_from(field_rows.len()).unwrap(),
        u32::try_from(method_rows.len()).unwrap(),
        &fieldrva_rows,
        resource_row,
        module_name_off,
        type_name_off,
        &field_rows,
        &method_rows,
    );

    let guid: Vec<u8> = vec![0u8; 16];
    let streams: Vec<Stream> = vec![
        Stream {
            name: "#~",
            bytes: tables,
        },
        Stream {
            name: "#Strings",
            bytes: strings,
        },
        Stream {
            name: "#US",
            bytes: us_heap,
        },
        Stream {
            name: "#GUID",
            bytes: guid,
        },
        Stream {
            name: "#Blob",
            bytes: blob,
        },
    ];

    let metadata: Vec<u8> = build_metadata(&streams);
    let resources_off: u32 = (METADATA_OFF + u32::try_from(metadata.len()).unwrap() + 3) & !3;
    let resources_rva: u32 = if resource_row.is_some() {
        TEXT_RVA + resources_off
    } else {
        0
    };

    let text_len: usize =
        (resources_off as usize + resource_entry.len() + 0x20).next_multiple_of(0x200);
    let mut text: Vec<u8> = vec![0u8; text_len];

    if let Some(body) = &spec.cctor_body {
        let off: usize = CCTOR_OFF as usize;
        text[off..off + body.len()].copy_from_slice(body);
    }
    if let Some(body) = &spec.decryptor_body {
        let off: usize = DECRYPTOR_OFF as usize;
        text[off..off + body.len()].copy_from_slice(body);
    }
    for (rva, data) in &field_data {
        let off: usize = (*rva - TEXT_RVA) as usize;
        text[off..off + data.len()].copy_from_slice(data);
    }
    let md_start: usize = METADATA_OFF as usize;
    text[md_start..md_start + metadata.len()].copy_from_slice(&metadata);
    if !resource_entry.is_empty() {
        let res_start: usize = resources_off as usize;
        text[res_start..res_start + resource_entry.len()].copy_from_slice(&resource_entry);
    }

    let clr: Vec<u8> = clr_header(
        TEXT_RVA + METADATA_OFF,
        u32::try_from(metadata.len()).unwrap(),
        if resource_row.is_some() {
            resources_rva
        } else {
            0
        },
        if resource_entry.is_empty() {
            0
        } else {
            u32::try_from(resource_entry.len()).unwrap()
        },
    );
    let clr_start: usize = CLR_OFF as usize;
    text[clr_start..clr_start + clr.len()].copy_from_slice(&clr);

    let mut img: Vec<u8> = assemble_pe(&[(b".text\0\0\0", &text, 0x6000_0020)], TEXT_RVA + CLR_OFF);
    embed_watermark_padding(&mut img, &spec.watermarks);
    img
}

fn embed_watermark_padding(img: &mut Vec<u8>, watermarks: &[&str]) {
    for w in watermarks {
        img.extend_from_slice(w.as_bytes());
        img.push(0);
    }
}

fn assemble_pe(sections: &[(&[u8; 8], &Vec<u8>, u32)], clr_rva: u32) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let opt_size: usize = 0xE0;
    let section_align: u32 = 0x2000;

    let mut raw_ptr: u32 = TEXT_RAW_PTR;
    let mut rva: u32 = TEXT_RVA;
    let mut layouts: Vec<(u32, u32, u32)> = Vec::with_capacity(sections.len());
    let mut total: usize = HEADERS_LEN;
    for (_, body, _) in sections {
        let raw_size: u32 = u32::try_from(body.len()).unwrap();
        layouts.push((rva, raw_ptr, raw_size));
        total += body.len();
        raw_ptr += raw_size;
        rva = (rva + raw_size).next_multiple_of(section_align);
    }
    let mut img: Vec<u8> = vec![0u8; total];

    img[0] = b'M';
    img[1] = b'Z';
    img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    img[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    img[pe_off + 6..pe_off + 8]
        .copy_from_slice(&u16::try_from(sections.len()).unwrap().to_le_bytes());
    img[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
    img[pe_off + 22..pe_off + 24].copy_from_slice(&0x2102u16.to_le_bytes());

    let opt_start: usize = pe_off + 24;
    img[opt_start..opt_start + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    img[opt_start + 16..opt_start + 20].copy_from_slice(&TEXT_RVA.to_le_bytes());
    img[opt_start + 28..opt_start + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    img[opt_start + 92..opt_start + 96].copy_from_slice(&16u32.to_le_bytes());
    let directories_start: usize = opt_start + 96;
    let clr_dir_offset: usize = directories_start + 14 * 8;
    img[clr_dir_offset..clr_dir_offset + 4].copy_from_slice(&clr_rva.to_le_bytes());
    img[clr_dir_offset + 4..clr_dir_offset + 8].copy_from_slice(&72u32.to_le_bytes());

    let sections_start: usize = opt_start + opt_size;
    for (i, (name, body, chars)) in sections.iter().enumerate() {
        let base: usize = sections_start + i * 40;
        let (sec_rva, sec_raw_ptr, sec_raw_size): (u32, u32, u32) = layouts[i];
        img[base..base + 8].copy_from_slice(*name);
        img[base + 8..base + 12].copy_from_slice(&sec_raw_size.to_le_bytes());
        img[base + 12..base + 16].copy_from_slice(&sec_rva.to_le_bytes());
        img[base + 16..base + 20].copy_from_slice(&sec_raw_size.to_le_bytes());
        img[base + 20..base + 24].copy_from_slice(&sec_raw_ptr.to_le_bytes());
        img[base + 36..base + 40].copy_from_slice(&chars.to_le_bytes());
        let start: usize = sec_raw_ptr as usize;
        img[start..start + body.len()].copy_from_slice(body);
    }
    img
}
