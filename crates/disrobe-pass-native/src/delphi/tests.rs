#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments
)]

use super::{
    DelphiClass, DelphiEra, DelphiForm, DelphiReport, analyze, detect_delphi,
    recover_delphi_classes, recover_dfm_resources,
};

const FORM1_HEX: &str = "545046300654466F726D3105466F726D31044C65667403C80003546F7002640557696474680340010648656967687403F0000743617074696F6E060C4C6F67696E2057696E646F7705436F6C6F720709636C42746E4661636507456E61626C6564090756697369626C650803546167022A0B426F7264657249636F6E730B0C626953797374656D4D656E750A62694D696E696D697A65000B426F726465725374796C65070862734469616C6F6700055445646974054564697431044C656674021003546F70021005576964746802790454657874060975736572206E616D6508526561644F6E6C790800000754427574746F6E07427574746F6E31044C656674021003546F70023C0743617074696F6E06034F274B0744656661756C74090B4D6F64616C526573756C740201000000";

const FORM1_EXPECTED: &str = "object Form1: TForm1
  Left = 200
  Top = 100
  Width = 320
  Height = 240
  Caption = 'Login Window'
  Color = clBtnFace
  Enabled = True
  Visible = False
  Tag = 42
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsDialog
  object Edit1: TEdit
    Left = 16
    Top = 16
    Width = 121
    Text = 'user name'
    ReadOnly = False
  end
  object Button1: TButton
    Left = 16
    Top = 60
    Caption = 'O''K'
    Default = True
    ModalResult = 1
  end
end
";

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        let hi: u8 = (bytes[i] as char).to_digit(16).unwrap() as u8;
        let lo: u8 = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn form1_bin() -> Vec<u8> {
    hex_to_bytes(FORM1_HEX)
}

fn form2_bin() -> Vec<u8> {
    let prefix: &str = "54504630095444617461466F726D0844617461466F726D044C65667404A086010003546F7002FB035461670478FDFF7F054974656D7301020A0214021E00054E6F7465730C11010000";
    let full: String = format!("{prefix}{}5A0000", "61".repeat(272));
    hex_to_bytes(&full)
}

fn form2_expected() -> String {
    let long: String = format!("{}Z", "a".repeat(272));
    format!(
        "object DataForm: TDataForm\n  Left = 100000\n  Top = -5\n  Tag = 2147483000\n  Items = (\n    10\n    20\n    30\n  )\n  Notes = '{long}'\nend\n"
    )
}

#[test]
fn dfm_decode_matches_fpc_reference_form1() {
    let forms: Vec<DelphiForm> = vec![decode_standalone(&form1_bin())];
    assert_eq!(forms[0].text, FORM1_EXPECTED);
    assert_eq!(forms[0].root_class, "TForm1");
    assert_eq!(forms[0].object_count, 3);
    assert!(!forms[0].truncated);
}

#[test]
fn dfm_decode_matches_fpc_reference_form2() {
    let decoded: DelphiForm = decode_standalone(&form2_bin());
    assert_eq!(decoded.text, form2_expected());
    assert_eq!(decoded.root_class, "TDataForm");
    assert!(!decoded.truncated);
}

fn decode_standalone(dfm: &[u8]) -> DelphiForm {
    let pe: Vec<u8> = pe_with_dfm_resource("TFORM1", dfm);
    let forms: Vec<DelphiForm> = recover_dfm_resources(&pe);
    assert_eq!(forms.len(), 1, "expected exactly one TPF0 resource");
    forms.into_iter().next().unwrap()
}

#[test]
fn resource_walk_reports_resource_name() {
    let pe: Vec<u8> = pe_with_dfm_resource("TFORM1", &form1_bin());
    let forms: Vec<DelphiForm> = recover_dfm_resources(&pe);
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].resource_name, "TFORM1");
    assert!(detect_delphi(&pe));
}

#[test]
fn dfm_decode_partial_on_unknown_value_type() {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    dfm.extend([2]);
    dfm.extend(b"TX");
    dfm.extend([0]);
    dfm.extend([1]);
    dfm.extend(b"P");
    dfm.extend([0xEE]);
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(!decoded.notes.is_empty());
    assert!(decoded.text.contains("P = "));
}

#[test]
fn recover_modern32_classes_with_props_methods_inheritance() {
    let (blob, _base): (Vec<u8>, u64) = build_modern32_blob();
    let pe: Vec<u8> = build_pe(
        false,
        0x0040_0000,
        &[(".data".to_owned(), 0x2000, blob)],
        None,
    );
    let mut classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    classes.sort_by(|a: &DelphiClass, b: &DelphiClass| a.name.cmp(&b.name));
    assert_eq!(classes.len(), 2, "expected TBase and TChild");

    let base: &DelphiClass = classes
        .iter()
        .find(|c: &&DelphiClass| c.name == "TBase")
        .unwrap();
    assert_eq!(base.era, DelphiEra::Modern32);
    assert_eq!(base.parent, None);
    assert_eq!(base.unit_name.as_deref(), Some("Unit1"));
    assert!(
        base.properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Caption"
                && p.type_name.as_deref() == Some("AnsiString")
                && p.inherited_from.is_none())
    );

    let child: &DelphiClass = classes
        .iter()
        .find(|c: &&DelphiClass| c.name == "TChild")
        .unwrap();
    assert_eq!(child.parent.as_deref(), Some("TBase"));
    assert!(
        child
            .properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Value"
                && p.type_name.as_deref() == Some("Integer")
                && p.inherited_from.is_none())
    );
    assert!(
        child
            .properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Caption"
                && p.inherited_from.as_deref() == Some("TBase"))
    );
    assert!(
        child
            .methods
            .iter()
            .any(|m: &super::DelphiMethod| m.name == "DoIt")
    );
}

#[test]
fn detect_legacy32_variant() {
    let blob: Vec<u8> = build_single_class_blob32(76, "TLegacy", 0x0040_2000);
    let pe: Vec<u8> = build_pe(
        false,
        0x0040_0000,
        &[(".data".to_owned(), 0x2000, blob)],
        None,
    );
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0].name, "TLegacy");
    assert_eq!(classes[0].era, DelphiEra::Legacy32);
}

#[test]
fn detect_modern64_variant() {
    let base: u64 = 0x1_4000_0000;
    let blob: Vec<u8> = build_single_class_blob64(base + 0x2000, "TWin64");
    let pe: Vec<u8> = build_pe(true, base, &[(".data".to_owned(), 0x2000, blob)], None);
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0].name, "TWin64");
    assert_eq!(classes[0].era, DelphiEra::Modern64);
}

#[test]
fn analyze_reports_no_rtti_when_absent() {
    let junk: Vec<u8> = (0..0x800u16)
        .map(|i: u16| (i.wrapping_mul(37) & 0xFF) as u8)
        .collect();
    let pe: Vec<u8> = build_pe(
        false,
        0x0040_0000,
        &[(".data".to_owned(), 0x2000, junk)],
        None,
    );
    let report: DelphiReport = analyze(&pe);
    assert!(!report.rtti_present);
    assert!(report.classes.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("no Delphi RTTI"))
    );
}

#[test]
#[cfg(windows)]
fn no_validated_classes_on_real_system_dlls() {
    let candidates: [&str; 3] = [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\ntdll.dll",
        r"C:\Windows\System32\user32.dll",
    ];
    let mut checked: usize = 0;
    for path in candidates {
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
            continue;
        };
        checked += 1;
        let report: DelphiReport = analyze(&bytes);
        assert!(
            report.classes.is_empty(),
            "{path} unexpectedly produced validated Delphi classes: {}",
            report.classes.len()
        );
        assert!(!report.rtti_present, "{path} unexpectedly reported RTTI");
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

#[test]
fn detect_delphi_marker_in_bytes() {
    let mut buf: Vec<u8> = b"MZ".to_vec();
    buf.extend(std::iter::repeat_n(0u8, 128));
    buf.extend_from_slice(b"compiled with Embarcadero Delphi 12");
    assert!(detect_delphi(&buf));
}

#[test]
fn dfm_deep_value_nesting_is_bounded_not_stack_overflow() {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    dfm.extend([1]);
    dfm.extend(b"T");
    dfm.extend([0]);
    dfm.extend([1]);
    dfm.extend(b"p");
    dfm.extend(std::iter::repeat_n(1u8, 200_000));
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(
        decoded
            .notes
            .iter()
            .any(|n: &String| n.contains("nesting exceeded the depth cap"))
    );
}

fn build_deep_property_bomb(levels: usize, props_at_leaf: usize) -> Vec<u8> {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    for _ in 0..levels {
        dfm.extend([1u8, b'T', 0u8, 0u8]);
    }
    dfm.extend([1u8, b'T', 0u8]);
    for _ in 0..props_at_leaf {
        dfm.extend([1u8, b'p', 8u8]);
    }
    dfm.extend([0u8, 0u8]);
    dfm.extend(std::iter::repeat_n(0u8, levels));
    dfm
}

#[test]
fn dfm_deep_nesting_output_is_capped_not_gigabytes() {
    let dfm: Vec<u8> = build_deep_property_bomb(300, 40_000);
    assert!(
        dfm.len() < 256 * 1024,
        "crafted input stays small: {} bytes",
        dfm.len()
    );
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(decoded.text.len() <= super::dfm::MAX_OUTPUT_BYTES);
    assert!(decoded.text.len() > 1024 * 1024);
    assert!(
        decoded
            .notes
            .iter()
            .any(|n: &String| n.contains("output size"))
    );
}

#[test]
fn hardening_never_panics_on_garbage() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        b"MZ".to_vec(),
        b"TPF0".to_vec(),
        b"TPF0\x01".to_vec(),
        vec![0xFFu8; 64],
        (0..4096u16)
            .map(|i: u16| (i.wrapping_mul(101) & 0xFF) as u8)
            .collect(),
    ];
    for input in &inputs {
        let _ = analyze(input);
        let _ = recover_delphi_classes(input);
        let _ = recover_dfm_resources(input);
        let _ = detect_delphi(input);
        let _ = super::dfm::decode(input);
    }
    let mut truncated_pe: Vec<u8> = build_pe(
        false,
        0x0040_0000,
        &[(".data".to_owned(), 0x2000, build_modern32_blob().0)],
        None,
    );
    truncated_pe.truncate(truncated_pe.len() / 2);
    let _ = analyze(&truncated_pe);
}

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn w64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn build_pe(
    plus: bool,
    image_base: u64,
    sections: &[(String, u32, Vec<u8>)],
    resource: Option<(u32, u32)>,
) -> Vec<u8> {
    let file_align: usize = 0x200;
    let sect_align: u32 = 0x1000;
    let opt_size: usize = if plus { 0xF0 } else { 0xE0 };
    let coff_off: usize = 0x84;
    let opt_off: usize = coff_off + 20;
    let sec_table_off: usize = opt_off + opt_size;
    let num: usize = sections.len();
    let raw_start: usize = align_up(sec_table_off + num * 40, file_align);

    let mut recs: Vec<(usize, u32, Vec<u8>, usize, String)> = Vec::new();
    let mut cur: usize = raw_start;
    for (name, rva, data) in sections {
        let rsize: usize = align_up(data.len().max(1), file_align);
        recs.push((cur, *rva, data.clone(), rsize, name.clone()));
        cur += rsize;
    }
    let file_size: usize = cur.max(raw_start + file_align);
    let mut buf: Vec<u8> = vec![0u8; file_size];

    buf[0] = b'M';
    buf[1] = b'Z';
    w32(&mut buf, 0x3C, 0x80);
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let machine: u16 = if plus { 0x8664 } else { 0x014C };
    w16(&mut buf, coff_off, machine);
    w16(&mut buf, coff_off + 2, num as u16);
    w16(&mut buf, coff_off + 16, opt_size as u16);

    let magic: u16 = if plus { 0x020B } else { 0x010B };
    w16(&mut buf, opt_off, magic);
    w32(&mut buf, opt_off + 16, 0x1000);
    if plus {
        w64(&mut buf, opt_off + 24, image_base);
    } else {
        w32(&mut buf, opt_off + 28, image_base as u32);
    }
    w32(&mut buf, opt_off + 32, sect_align);
    w32(&mut buf, opt_off + 36, file_align as u32);
    let max_end: u32 = recs
        .iter()
        .map(|(_, rva, data, _, _)| {
            let end: u32 = rva.saturating_add(data.len() as u32);
            (end.div_ceil(sect_align)) * sect_align
        })
        .max()
        .unwrap_or(0x2000);
    w32(&mut buf, opt_off + 56, max_end);

    let dir_count_off: usize = if plus { opt_off + 108 } else { opt_off + 92 };
    w32(&mut buf, dir_count_off, 16);
    let dir_table: usize = dir_count_off + 4;
    if let Some((rva, size)) = resource {
        w32(&mut buf, dir_table + 2 * 8, rva);
        w32(&mut buf, dir_table + 2 * 8 + 4, size);
    }

    for (i, (off, rva, data, rsize, name)) in recs.iter().enumerate() {
        let so: usize = sec_table_off + i * 40;
        let mut nm: [u8; 8] = [0u8; 8];
        let nb: &[u8] = name.as_bytes();
        let n: usize = nb.len().min(8);
        nm[..n].copy_from_slice(&nb[..n]);
        buf[so..so + 8].copy_from_slice(&nm);
        w32(&mut buf, so + 8, data.len() as u32);
        w32(&mut buf, so + 12, *rva);
        w32(&mut buf, so + 16, *rsize as u32);
        w32(&mut buf, so + 20, *off as u32);
        w32(&mut buf, so + 36, 0x4000_0040);
        buf[*off..*off + data.len()].copy_from_slice(data);
    }

    buf
}

fn pe_with_dfm_resource(res_name: &str, dfm: &[u8]) -> Vec<u8> {
    let res_base_rva: u32 = 0x4000;
    let (rsrc, size): (Vec<u8>, u32) = build_rsrc(res_base_rva, res_name, dfm);
    build_pe(
        false,
        0x0040_0000,
        &[(".rsrc".to_owned(), res_base_rva, rsrc)],
        Some((res_base_rva, size)),
    )
}

fn build_rsrc(res_base_rva: u32, res_name: &str, dfm: &[u8]) -> (Vec<u8>, u32) {
    let dir1_off: usize = 0;
    let dir2_off: usize = 24;
    let dir3_off: usize = 48;
    let name_off: usize = 72;
    let name_bytes: usize = 2 + res_name.len() * 2;
    let data_entry_off: usize = align_up(name_off + name_bytes, 4);
    let dfm_off: usize = align_up(data_entry_off + 16, 4);
    let total: usize = dfm_off + dfm.len();
    let mut buf: Vec<u8> = vec![0u8; total];

    w16(&mut buf, dir1_off + 12, 0);
    w16(&mut buf, dir1_off + 14, 1);
    w32(&mut buf, dir1_off + 16, 10);
    w32(&mut buf, dir1_off + 20, 0x8000_0000 | dir2_off as u32);

    w16(&mut buf, dir2_off + 12, 1);
    w16(&mut buf, dir2_off + 14, 0);
    w32(&mut buf, dir2_off + 16, 0x8000_0000 | name_off as u32);
    w32(&mut buf, dir2_off + 20, 0x8000_0000 | dir3_off as u32);

    w16(&mut buf, dir3_off + 12, 0);
    w16(&mut buf, dir3_off + 14, 1);
    w32(&mut buf, dir3_off + 16, 0x0409);
    w32(&mut buf, dir3_off + 20, data_entry_off as u32);

    w16(&mut buf, name_off, res_name.len() as u16);
    for (i, ch) in res_name.encode_utf16().enumerate() {
        w16(&mut buf, name_off + 2 + i * 2, ch);
    }

    w32(&mut buf, data_entry_off, res_base_rva + dfm_off as u32);
    w32(&mut buf, data_entry_off + 4, dfm.len() as u32);

    buf[dfm_off..dfm_off + dfm.len()].copy_from_slice(dfm);
    (buf, total as u32)
}

fn short_string(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = vec![s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

struct Blob {
    buf: Vec<u8>,
    base_va: u64,
    ptr: usize,
}

impl Blob {
    fn new(base_va: u64, ptr: usize) -> Self {
        Self {
            buf: Vec::new(),
            base_va,
            ptr,
        }
    }

    fn va(&self, off: usize) -> u64 {
        self.base_va + off as u64
    }

    fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    fn put_bytes(&mut self, b: &[u8]) -> usize {
        let at: usize = self.buf.len();
        self.buf.extend_from_slice(b);
        at
    }

    fn put_ss(&mut self, s: &str) -> u64 {
        let at: usize = self.put_bytes(&short_string(s));
        self.va(at)
    }

    fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_ptr(&mut self, v: u64) {
        if self.ptr == 8 {
            self.buf.extend_from_slice(&v.to_le_bytes());
        } else {
            self.buf.extend_from_slice(&(v as u32).to_le_bytes());
        }
    }

    fn put_simple_typeinfo(&mut self, kind: u8, name: &str) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u8(kind);
        self.put_bytes(&short_string(name));
        at
    }

    fn put_class_typeinfo(&mut self, name: &str, unit: &str, props: &[(&str, u64)]) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u8(7);
        self.put_bytes(&short_string(name));
        self.put_ptr(0);
        self.put_ptr(0);
        self.put_u16(props.len() as u16);
        self.put_bytes(&short_string(unit));
        self.put_u16(props.len() as u16);
        for (pname, ptype) in props {
            self.put_ptr(*ptype);
            self.put_ptr(0);
            self.put_ptr(0);
            self.put_ptr(0);
            self.put_u32(0);
            self.put_u32(0);
            self.put_u16(0);
            self.put_bytes(&short_string(pname));
        }
        at
    }

    fn put_method_table(&mut self, methods: &[(&str, u64)]) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u16(methods.len() as u16);
        for (name, addr) in methods {
            let size: u16 = (2 + self.ptr + 1 + name.len()) as u16;
            self.put_u16(size);
            self.put_ptr(*addr);
            self.put_bytes(&short_string(name));
        }
        at
    }

    fn put_vmt(
        &mut self,
        self_abs: usize,
        slot_type_info: i64,
        slot_method: i64,
        slot_class_name: i64,
        slot_instance: i64,
        slot_parent: i64,
        class_name_va: u64,
        type_info_va: u64,
        method_table_va: u64,
        instance_size: u32,
        parent_va: u64,
    ) -> u64 {
        self.align(self.ptr);
        let region_off: usize = self.buf.len();
        let c_va: u64 = self.va(region_off + self_abs);
        for _ in 0..(self_abs + 4 * self.ptr) {
            self.buf.push(0);
        }
        let write_ptr = |b: &mut Vec<u8>, base: usize, slot: i64, val: u64, ptr: usize| {
            let at: usize = (base as i64 + self_abs as i64 + slot) as usize;
            if ptr == 8 {
                b[at..at + 8].copy_from_slice(&val.to_le_bytes());
            } else {
                b[at..at + 4].copy_from_slice(&(val as u32).to_le_bytes());
            }
        };
        let self_slot: usize = region_off;
        if self.ptr == 8 {
            self.buf[self_slot..self_slot + 8].copy_from_slice(&c_va.to_le_bytes());
        } else {
            self.buf[self_slot..self_slot + 4].copy_from_slice(&(c_va as u32).to_le_bytes());
        }
        write_ptr(
            &mut self.buf,
            region_off,
            slot_type_info,
            type_info_va,
            self.ptr,
        );
        write_ptr(
            &mut self.buf,
            region_off,
            slot_method,
            method_table_va,
            self.ptr,
        );
        write_ptr(
            &mut self.buf,
            region_off,
            slot_class_name,
            class_name_va,
            self.ptr,
        );
        let inst_at: usize = (region_off as i64 + self_abs as i64 + slot_instance) as usize;
        self.buf[inst_at..inst_at + 4].copy_from_slice(&instance_size.to_le_bytes());
        write_ptr(&mut self.buf, region_off, slot_parent, parent_va, self.ptr);
        c_va
    }
}

fn build_modern32_blob() -> (Vec<u8>, u64) {
    let base_va: u64 = 0x0040_2000;
    let mut b: Blob = Blob::new(base_va, 4);
    let cn_base: u64 = b.put_ss("TBase");
    let cn_child: u64 = b.put_ss("TChild");
    let ti_int: u64 = b.put_simple_typeinfo(1, "Integer");
    let ti_astr: u64 = b.put_simple_typeinfo(10, "AnsiString");
    let ti_base: u64 = b.put_class_typeinfo("TBase", "Unit1", &[("Caption", ti_astr)]);
    let ti_child: u64 = b.put_class_typeinfo("TChild", "Unit1", &[("Value", ti_int)]);
    let mt_child: u64 = b.put_method_table(&[("DoIt", 0x0040_1000)]);
    let c_base: u64 = b.put_vmt(88, -72, -64, -56, -52, -48, cn_base, ti_base, 0, 20, 0);
    let _c_child: u64 = b.put_vmt(
        88, -72, -64, -56, -52, -48, cn_child, ti_child, mt_child, 24, c_base,
    );
    (b.buf, base_va)
}

fn build_single_class_blob32(self_abs: usize, name: &str, base_va: u64) -> Vec<u8> {
    let (ti, mt): (i64, i64) = if self_abs == 76 {
        (-60, -52)
    } else {
        (-72, -64)
    };
    let (cn, inst, par): (i64, i64, i64) = if self_abs == 76 {
        (-44, -40, -36)
    } else {
        (-56, -52, -48)
    };
    let mut b: Blob = Blob::new(base_va, 4);
    let cn_va: u64 = b.put_ss(name);
    let _c: u64 = b.put_vmt(self_abs, ti, mt, cn, inst, par, cn_va, 0, 0, 16, 0);
    b.buf
}

fn build_single_class_blob64(base_va: u64, name: &str) -> Vec<u8> {
    let mut b: Blob = Blob::new(base_va, 8);
    let cn_va: u64 = b.put_ss(name);
    let _c: u64 = b.put_vmt(176, -144, -128, -112, -104, -96, cn_va, 0, 0, 32, 0);
    b.buf
}
