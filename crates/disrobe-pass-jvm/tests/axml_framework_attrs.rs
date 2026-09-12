#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_jvm::{AxmlTree, parse_axml};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NS: u16 = 0x0100;
const RES_XML_END_NS: u16 = 0x0101;
const RES_XML_START_ELEM: u16 = 0x0102;
const RES_XML_END_ELEM: u16 = 0x0103;

fn string_pool(strings: &[&str]) -> Vec<u8> {
    let mut offsets: Vec<u32> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let header: u16 = 28;
    let index_size: u32 = offsets.len() as u32 * 4;
    let strings_start: u32 = u32::from(header) + index_size;
    let size: u32 = strings_start + data.len() as u32;
    let mut pool: Vec<u8> = Vec::new();
    pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    pool.extend_from_slice(&header.to_le_bytes());
    pool.extend_from_slice(&size.to_le_bytes());
    pool.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);
    pool
}

fn resource_map(ids: &[u32]) -> Vec<u8> {
    let header: u16 = 8;
    let size: u32 = u32::from(header) + (ids.len() as u32) * 4;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

fn obfuscated_manifest() -> Vec<u8> {
    let strings: [&str; 5] = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "activity",
        "",
        "",
    ];
    let pool: Vec<u8> = string_pool(&strings);
    let rmap: Vec<u8> = resource_map(&[0, 0, 0, 0x0101_0003, 0x0101_0010]);

    let mut start_ns: Vec<u8> = Vec::new();
    start_ns.extend_from_slice(&RES_XML_START_NS.to_le_bytes());
    start_ns.extend_from_slice(&16u16.to_le_bytes());
    start_ns.extend_from_slice(&24u32.to_le_bytes());
    start_ns.extend_from_slice(&1u32.to_le_bytes());
    start_ns.extend_from_slice(&u32::MAX.to_le_bytes());
    start_ns.extend_from_slice(&0u32.to_le_bytes());
    start_ns.extend_from_slice(&1u32.to_le_bytes());

    let attrs: [(u32, u32, u8, u32); 2] = [(3, 2, 0x03, 2), (4, u32::MAX, 0x12, 1)];
    let elem_size: u32 = 16 + 20 + (attrs.len() as u32) * 20;
    let mut elem: Vec<u8> = Vec::new();
    elem.extend_from_slice(&RES_XML_START_ELEM.to_le_bytes());
    elem.extend_from_slice(&16u16.to_le_bytes());
    elem.extend_from_slice(&elem_size.to_le_bytes());
    elem.extend_from_slice(&1u32.to_le_bytes());
    elem.extend_from_slice(&u32::MAX.to_le_bytes());
    elem.extend_from_slice(&u32::MAX.to_le_bytes());
    elem.extend_from_slice(&2u32.to_le_bytes());
    elem.extend_from_slice(&0x0014u16.to_le_bytes());
    elem.extend_from_slice(&0x0014u16.to_le_bytes());
    elem.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    elem.extend_from_slice(&0u16.to_le_bytes());
    elem.extend_from_slice(&0u16.to_le_bytes());
    elem.extend_from_slice(&0u16.to_le_bytes());
    for (name_idx, raw_idx, vtype, data) in attrs {
        elem.extend_from_slice(&1u32.to_le_bytes());
        elem.extend_from_slice(&name_idx.to_le_bytes());
        elem.extend_from_slice(&raw_idx.to_le_bytes());
        elem.extend_from_slice(&0x0008u16.to_le_bytes());
        elem.push(0);
        elem.push(vtype);
        elem.extend_from_slice(&data.to_le_bytes());
    }

    let mut end_elem: Vec<u8> = Vec::new();
    end_elem.extend_from_slice(&RES_XML_END_ELEM.to_le_bytes());
    end_elem.extend_from_slice(&16u16.to_le_bytes());
    end_elem.extend_from_slice(&24u32.to_le_bytes());
    end_elem.extend_from_slice(&1u32.to_le_bytes());
    end_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    end_elem.extend_from_slice(&u32::MAX.to_le_bytes());
    end_elem.extend_from_slice(&2u32.to_le_bytes());

    let mut end_ns: Vec<u8> = Vec::new();
    end_ns.extend_from_slice(&RES_XML_END_NS.to_le_bytes());
    end_ns.extend_from_slice(&16u16.to_le_bytes());
    end_ns.extend_from_slice(&24u32.to_le_bytes());
    end_ns.extend_from_slice(&1u32.to_le_bytes());
    end_ns.extend_from_slice(&u32::MAX.to_le_bytes());
    end_ns.extend_from_slice(&0u32.to_le_bytes());
    end_ns.extend_from_slice(&1u32.to_le_bytes());

    let body_len: u32 =
        (pool.len() + rmap.len() + start_ns.len() + elem.len() + end_elem.len() + end_ns.len())
            as u32;
    let total: u32 = 8 + body_len;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&rmap);
    out.extend_from_slice(&start_ns);
    out.extend_from_slice(&elem);
    out.extend_from_slice(&end_elem);
    out.extend_from_slice(&end_ns);
    out
}

#[test]
fn empty_attr_names_recovered_from_resource_map() {
    let bytes: Vec<u8> = obfuscated_manifest();
    let tree: AxmlTree = parse_axml(&bytes).expect("obfuscated manifest parses");
    let xml: String = tree.to_xml();

    assert!(
        xml.contains("android:name=\"activity\""),
        "empty attr-name string (idx 0) recovered to android:name via resource map id 0x01010003; got:\n{xml}"
    );
    assert!(
        xml.contains("android:exported=\"true\""),
        "second empty attr-name recovered to android:exported via id 0x01010010; got:\n{xml}"
    );
}
