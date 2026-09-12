use std::time::Duration;

use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{format_python_no_format_with_header, provenance_header};

#[test]
fn provenance_header_exact_format() {
    let version: PyVersion = PyVersion::V3_13;
    let header: String = provenance_header(&version, Duration::from_millis(1200)).render();
    assert_eq!(
        header,
        "# Decompiled in 1.2s with Disrobe (https://github.com/1-3-7/disrobe)\n# Python 3.13\n"
    );
}

#[test]
fn provenance_header_zero_ms() {
    let version: PyVersion = PyVersion::V3_12;
    let header: String = provenance_header(&version, Duration::from_millis(0)).render();
    assert_eq!(
        header,
        "# Decompiled in 0ms with Disrobe (https://github.com/1-3-7/disrobe)\n# Python 3.12\n"
    );
}

#[test]
fn provenance_header_prepended_to_body_preserves_body() {
    let version: PyVersion = PyVersion::V3_14;
    let body: &str = "x = 1\n";
    let out: String =
        format_python_no_format_with_header(body, &version, Duration::from_millis(50));
    assert!(
        out.starts_with("# Decompiled in 50ms with Disrobe (https://github.com/1-3-7/disrobe)\n")
    );
    assert!(out.contains("\n# Python 3.14\n"));
    assert!(out.ends_with("x = 1\n"));
}
