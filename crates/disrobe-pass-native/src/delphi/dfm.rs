const VA_NULL: u8 = 0;
const VA_LIST: u8 = 1;
const VA_INT8: u8 = 2;
const VA_INT16: u8 = 3;
const VA_INT32: u8 = 4;
const VA_EXTENDED: u8 = 5;
const VA_STRING: u8 = 6;
const VA_IDENT: u8 = 7;
const VA_FALSE: u8 = 8;
const VA_TRUE: u8 = 9;
const VA_BINARY: u8 = 10;
const VA_SET: u8 = 11;
const VA_LSTRING: u8 = 12;
const VA_NIL: u8 = 13;
const VA_COLLECTION: u8 = 14;
const VA_SINGLE: u8 = 15;
const VA_CURRENCY: u8 = 16;
const VA_DATE: u8 = 17;
const VA_WSTRING: u8 = 18;
const VA_INT64: u8 = 19;
const VA_UTF8STRING: u8 = 20;
const VA_DOUBLE: u8 = 21;

const MAX_DEPTH: usize = 512;
const MAX_OBJECTS: usize = 200_000;

#[derive(Debug, Clone)]
pub(super) struct DfmDecoded {
    pub text: String,
    pub root_class: String,
    pub object_count: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end: usize = self.pos.checked_add(n)?;
        let slice: &[u8] = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        let b: u8 = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn unread(&mut self) {
        self.pos = self.pos.saturating_sub(1);
    }

    fn u16le(&mut self) -> Option<u16> {
        let s: &[u8] = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32le(&mut self) -> Option<u32> {
        let s: &[u8] = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64le(&mut self) -> Option<u64> {
        let s: &[u8] = self.take(8)?;
        Some(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn shortstring(&mut self) -> Option<Vec<u8>> {
        let len: usize = self.u8()? as usize;
        Some(self.take(len)?.to_vec())
    }

    fn lstring(&mut self) -> Option<Vec<u8>> {
        let len: usize = self.u32le()? as usize;
        Some(self.take(len)?.to_vec())
    }

    fn wstring(&mut self) -> Option<Vec<u16>> {
        let len: usize = self.u32le()? as usize;
        let bytes: &[u8] = self.take(len.checked_mul(2)?)?;
        Some(
            bytes
                .chunks_exact(2)
                .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                .collect(),
        )
    }
}

struct State {
    out: String,
    object_count: usize,
    truncated: bool,
    notes: Vec<String>,
    root_class: String,
}

impl State {
    fn flag(&mut self, note: &str) {
        self.truncated = true;
        if !self.notes.iter().any(|n: &String| n == note) {
            self.notes.push(note.to_owned());
        }
    }
}

pub(super) fn decode(data: &[u8]) -> Option<DfmDecoded> {
    if !data.starts_with(b"TPF0") {
        return None;
    }
    let mut cur: Cursor<'_> = Cursor::new(data);
    cur.pos = 4;
    let mut state: State = State {
        out: String::new(),
        object_count: 0,
        truncated: false,
        notes: Vec::new(),
        root_class: String::new(),
    };
    if read_object(&mut cur, &mut state, "", 0).is_none() {
        state.flag("stream ended before a complete object");
    }
    Some(DfmDecoded {
        text: state.out,
        root_class: state.root_class,
        object_count: state.object_count,
        truncated: state.truncated,
        notes: state.notes,
    })
}

fn read_object(cur: &mut Cursor<'_>, st: &mut State, indent: &str, depth: usize) -> Option<()> {
    if depth >= MAX_DEPTH {
        st.flag("object nesting exceeded the depth cap");
        return None;
    }
    if st.object_count >= MAX_OBJECTS {
        st.flag("object count exceeded the cap");
        return None;
    }

    let first: u8 = cur.u8()?;
    let mut flags: u8 = 0;
    let mut child_pos: Option<i64> = None;
    if first & 0xF0 == 0xF0 {
        flags = first;
        if first & 0x02 != 0 {
            child_pos = Some(read_int(cur)?);
        }
    } else {
        cur.unread();
    }

    let class_name: Vec<u8> = cur.shortstring()?;
    let object_name: Vec<u8> = cur.shortstring()?;
    let class_str: String = String::from_utf8_lossy(&class_name).into_owned();
    let name_str: String = String::from_utf8_lossy(&object_name).into_owned();

    if st.root_class.is_empty() {
        class_str.clone_into(&mut st.root_class);
    }
    st.object_count += 1;

    st.out.push_str(indent);
    if flags & 0x01 != 0 {
        st.out.push_str("inherited");
    } else if flags & 0x04 != 0 {
        st.out.push_str("inline");
    } else {
        st.out.push_str("object");
    }
    st.out.push(' ');
    if !name_str.is_empty() {
        st.out.push_str(&name_str);
        st.out.push_str(": ");
    }
    st.out.push_str(&class_str);
    if let Some(pos) = child_pos {
        st.out.push('[');
        st.out.push_str(&pos.to_string());
        st.out.push(']');
    }
    st.out.push('\n');

    let child_indent: String = format!("{indent}  ");
    read_prop_list(cur, st, &child_indent, depth)?;

    loop {
        let b: u8 = cur.u8()?;
        if b == 0 {
            break;
        }
        cur.unread();
        read_object(cur, st, &child_indent, depth + 1)?;
    }

    st.out.push_str(indent);
    st.out.push_str("end\n");
    Some(())
}

fn read_prop_list(cur: &mut Cursor<'_>, st: &mut State, indent: &str, depth: usize) -> Option<()> {
    if depth >= MAX_DEPTH {
        st.flag("value nesting exceeded the depth cap");
        return None;
    }
    loop {
        let b: u8 = cur.u8()?;
        if b == 0 {
            break;
        }
        cur.unread();
        let name: Vec<u8> = cur.shortstring()?;
        st.out.push_str(indent);
        st.out.push_str(&String::from_utf8_lossy(&name));
        st.out.push_str(" = ");
        let vt: u8 = cur.u8()?;
        process_value(cur, st, indent, vt, depth)?;
    }
    Some(())
}

fn read_int(cur: &mut Cursor<'_>) -> Option<i64> {
    let vt: u8 = cur.u8()?;
    read_int_typed(cur, vt)
}

fn read_int_typed(cur: &mut Cursor<'_>, vt: u8) -> Option<i64> {
    match vt {
        VA_INT8 => Some(i64::from(cur.u8()? as i8)),
        VA_INT16 => Some(i64::from(cur.u16le()? as i16)),
        VA_INT32 => Some(i64::from(cur.u32le()? as i32)),
        VA_INT64 => Some(cur.u64le()? as i64),
        _ => None,
    }
}

fn process_value(
    cur: &mut Cursor<'_>,
    st: &mut State,
    indent: &str,
    vt: u8,
    depth: usize,
) -> Option<()> {
    if depth >= MAX_DEPTH {
        st.flag("value nesting exceeded the depth cap");
        return None;
    }
    match vt {
        VA_LIST => {
            st.out.push('(');
            let mut first: bool = true;
            let inner: String = format!("{indent}  ");
            loop {
                let ivt: u8 = cur.u8()?;
                if ivt == VA_NULL {
                    break;
                }
                if first {
                    st.out.push('\n');
                    first = false;
                }
                st.out.push_str(&inner);
                process_value(cur, st, &inner, ivt, depth + 1)?;
            }
            st.out.push_str(indent);
            st.out.push_str(")\n");
        }
        VA_INT8 => push_line(st, &i64::from(cur.u8()? as i8).to_string()),
        VA_INT16 => push_line(st, &i64::from(cur.u16le()? as i16).to_string()),
        VA_INT32 => push_line(st, &i64::from(cur.u32le()? as i32).to_string()),
        VA_INT64 => push_line(st, &(cur.u64le()? as i64).to_string()),
        VA_EXTENDED => {
            let bytes: &[u8] = cur.take(10)?;
            push_line(st, &format_extended(bytes));
        }
        VA_SINGLE => {
            let v: f32 = f32::from_le_bytes(cur.take(4)?.try_into().ok()?);
            push_line(st, &format_float(f64::from(v)));
        }
        VA_DOUBLE => {
            let v: f64 = f64::from_bits(cur.u64le()?);
            push_line(st, &format_float(v));
        }
        VA_DATE => {
            let v: f64 = f64::from_bits(cur.u64le()?);
            push_line(st, &format_float(v));
        }
        VA_CURRENCY => {
            let raw: i64 = cur.u64le()? as i64;
            push_line(st, &format_currency(raw));
        }
        VA_STRING => {
            let s: Vec<u8> = cur.shortstring()?;
            push_line(st, &encode_bytes(&s));
        }
        VA_LSTRING => {
            let s: Vec<u8> = cur.lstring()?;
            push_line(st, &encode_bytes(&s));
        }
        VA_UTF8STRING => {
            let s: Vec<u8> = cur.lstring()?;
            push_line(st, &encode_utf8(&s));
        }
        VA_WSTRING => {
            let s: Vec<u16> = cur.wstring()?;
            push_line(st, &encode_wide(&s));
        }
        VA_IDENT => {
            let s: Vec<u8> = cur.shortstring()?;
            push_line(st, &String::from_utf8_lossy(&s));
        }
        VA_FALSE => push_line(st, "False"),
        VA_TRUE => push_line(st, "True"),
        VA_NIL => push_line(st, "nil"),
        VA_NULL => push_line(st, "Null"),
        VA_BINARY => {
            let len: usize = cur.u32le()? as usize;
            let bytes: &[u8] = cur.take(len)?;
            st.out.push_str("{\n");
            for chunk in bytes.chunks(32) {
                st.out.push_str(indent);
                st.out.push_str("  ");
                for byte in chunk {
                    st.out.push_str(&format!("{byte:02X}"));
                }
                st.out.push('\n');
            }
            st.out.push_str(indent);
            st.out.push_str("}\n");
        }
        VA_SET => {
            st.out.push('[');
            let mut first: bool = true;
            loop {
                let elem: Vec<u8> = cur.shortstring()?;
                if elem.is_empty() {
                    break;
                }
                if !first {
                    st.out.push_str(", ");
                }
                first = false;
                st.out.push_str(&String::from_utf8_lossy(&elem));
            }
            st.out.push_str("]\n");
        }
        VA_COLLECTION => {
            st.out.push('<');
            let item_indent: String = format!("{indent}    ");
            loop {
                let b: u8 = cur.u8()?;
                if b == 0 {
                    break;
                }
                cur.unread();
                st.out.push_str(indent);
                st.out.push('\n');
                st.out.push_str(indent);
                st.out.push_str("  item");
                let ivt: u8 = cur.u8()?;
                if ivt != VA_LIST {
                    let idx: i64 = read_int_typed(cur, ivt)?;
                    st.out.push('[');
                    st.out.push_str(&idx.to_string());
                    st.out.push(']');
                }
                st.out.push('\n');
                read_prop_list(cur, st, &item_indent, depth + 1)?;
                st.out.push_str(indent);
                st.out.push_str("  end");
            }
            st.out.push_str(">\n");
        }
        _ => {
            st.flag(&format!("unrecognized value type byte {vt}"));
            return None;
        }
    }
    Some(())
}

fn push_line(st: &mut State, s: &str) {
    st.out.push_str(s);
    st.out.push('\n');
}

fn encode_bytes(bytes: &[u8]) -> String {
    let codes: Vec<u32> = bytes.iter().map(|b: &u8| u32::from(*b)).collect();
    out_chars(&codes)
}

fn encode_utf8(bytes: &[u8]) -> String {
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
    let codes: Vec<u32> = text.chars().map(|c: char| c as u32).collect();
    out_chars(&codes)
}

fn encode_wide(units: &[u16]) -> String {
    let codes: Vec<u32> = char::decode_utf16(units.iter().copied())
        .map(|r: Result<char, _>| r.map_or(0xFFFD, |c: char| c as u32))
        .collect();
    out_chars(&codes)
}

fn out_chars(codes: &[u32]) -> String {
    if codes.is_empty() {
        return "''".to_owned();
    }
    let mut res: String = String::new();
    let mut in_string: bool = false;
    for &w in codes {
        let mut new_in: bool = in_string;
        let mut piece: String = if w == 0x27 {
            if !in_string {
                new_in = true;
            }
            "''".to_owned()
        } else if (0x20..0x7F).contains(&w) {
            if !in_string {
                new_in = true;
            }
            char::from_u32(w).map_or_else(|| "?".to_owned(), |c: char| c.to_string())
        } else {
            if in_string {
                new_in = false;
            }
            format!("#{w}")
        };
        if new_in != in_string {
            piece = format!("'{piece}");
            in_string = new_in;
        }
        res.push_str(&piece);
    }
    if in_string {
        res.push('\'');
    }
    res
}

#[allow(clippy::float_cmp)]
fn format_float(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        let mut s: String = format!("{v}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        s
    }
}

fn format_currency(raw: i64) -> String {
    let scaled: f64 = raw as f64 / 10_000.0;
    format_float(scaled)
}

fn format_extended(bytes: &[u8]) -> String {
    if bytes.len() < 10 {
        return "0".to_owned();
    }
    let mantissa: u64 = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let se: u16 = u16::from_le_bytes([bytes[8], bytes[9]]);
    let sign: bool = se & 0x8000 != 0;
    let exponent: i32 = i32::from(se & 0x7FFF);
    if exponent == 0 && mantissa == 0 {
        return "0".to_owned();
    }
    if exponent == 0x7FFF {
        return if sign {
            "-INF".to_owned()
        } else {
            "INF".to_owned()
        };
    }
    let unbiased: i32 = exponent - 16383;
    let value: f64 = (mantissa as f64) / (2f64.powi(63)) * 2f64.powi(unbiased);
    let signed: f64 = if sign { -value } else { value };
    format_float(signed)
}
