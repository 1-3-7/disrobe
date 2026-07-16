use crate::pdb_cxx::EmittedUdt;

const OFFSETOF_MACRO: &str = "DR_PDB_OFFSETOF";

pub fn render_static_assert_tu(header_text: &str, udts: &[EmittedUdt]) -> String {
    let mut out: String = String::new();
    out.push_str("#if defined(__clang__) || defined(__GNUC__)\n");
    out.push_str(&format!(
        "#define {OFFSETOF_MACRO}(T, m) ((unsigned long long)__builtin_offsetof(T, m))\n"
    ));
    out.push_str("#else\n");
    out.push_str(&format!(
        "#define {OFFSETOF_MACRO}(T, m) ((unsigned long long)&reinterpret_cast<const volatile char&>((((T*)0)->m)))\n"
    ));
    out.push_str("#endif\n");
    out.push_str(header_text);
    out.push('\n');
    for udt in udts {
        render_udt_assertions(&mut out, udt);
    }
    out
}

fn render_udt_assertions(out: &mut String, udt: &EmittedUdt) {
    let name: &str = &udt.emitted_name;
    out.push_str(&format!(
        "static_assert(sizeof({name}) == {}ULL, \"size mismatch for {name}\");\n",
        udt.byte_size
    ));
    for field in &udt.fields {
        if field.is_static || field.bitfield.is_some() {
            continue;
        }
        out.push_str(&format!(
            "static_assert({OFFSETOF_MACRO}({name}, {}) == {}ULL, \"offset mismatch for {name}::{}\");\n",
            field.emitted_name, field.offset, field.emitted_name
        ));
    }
}

#[must_use]
pub fn perturb_first_offset(rendered: &str) -> Option<String> {
    let anchor: String = format!("static_assert({OFFSETOF_MACRO}(");
    let marker: &str = " == ";
    let start: usize = rendered.find(&anchor)?;
    let rest: &str = &rendered[start..];
    let eq_pos: usize = rest.find(marker)?;
    let value_start: usize = start + eq_pos + marker.len();
    let digits_end: usize = rendered[value_start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(rendered.len(), |i: usize| value_start + i);
    let original: &str = &rendered[value_start..digits_end];
    let parsed: u64 = original.parse().ok()?;
    let corrupted: u64 = parsed.wrapping_add(1);
    let mut out: String = String::with_capacity(rendered.len());
    out.push_str(&rendered[..value_start]);
    out.push_str(&corrupted.to_string());
    out.push_str(&rendered[digits_end..]);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::pdb_cxx::{EmittedField, UdtTagKeyword};

    fn sample_udt() -> EmittedUdt {
        EmittedUdt {
            type_index: 0x1000,
            tag_keyword: UdtTagKeyword::Struct,
            emitted_name: "Point".to_owned(),
            original_name: "Point".to_owned(),
            byte_size: 8,
            bases: Vec::new(),
            fields: vec![
                EmittedField {
                    emitted_name: "x".to_owned(),
                    original_name: "x".to_owned(),
                    declaration: "int x".to_owned(),
                    offset: 0,
                    byte_size: Some(4),
                    bitfield: None,
                    is_static: false,
                },
                EmittedField {
                    emitted_name: "y".to_owned(),
                    original_name: "y".to_owned(),
                    declaration: "int y".to_owned(),
                    offset: 4,
                    byte_size: Some(4),
                    bitfield: None,
                    is_static: false,
                },
            ],
            degraded: false,
            depends_on: Vec::new(),
        }
    }

    #[test]
    fn renders_size_and_offset_assertions() {
        let rendered: String =
            render_static_assert_tu("struct Point { int x; int y; };", &[sample_udt()]);
        assert!(rendered.contains("sizeof(Point) == 8ULL"));
        assert!(rendered.contains(&format!("{OFFSETOF_MACRO}(Point, x) == 0ULL")));
        assert!(rendered.contains(&format!("{OFFSETOF_MACRO}(Point, y) == 4ULL")));
    }

    #[test]
    fn perturbation_changes_exactly_one_expected_value() {
        let rendered: String =
            render_static_assert_tu("struct Point { int x; int y; };", &[sample_udt()]);
        let corrupted: String =
            perturb_first_offset(&rendered).expect("perturb must find an offsetof assertion");
        assert_ne!(rendered, corrupted);
        assert!(corrupted.contains(&format!("{OFFSETOF_MACRO}(Point, x) == 1ULL")));
    }
}
