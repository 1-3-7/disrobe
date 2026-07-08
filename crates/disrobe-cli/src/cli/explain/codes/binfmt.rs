use super::super::CodeEntry;

pub(super) const BINFMT: &[CodeEntry] = &[
    CodeEntry {
        code: "DR-BINFMT-0065",
        title: "eszip module-graph archive parse failed",
        description: "the Deno eszip module-graph archive did not parse.",
        common_causes: &["truncated eszip archive", "unsupported eszip version"],
        common_fixes: &["confirm the input is a Deno eszip v2 through v2.3 archive"],
        crate_path: "crates/disrobe-binfmt/src/error.rs",
    },
    CodeEntry {
        code: "DR-BINFMT-0066",
        title: ".NET single-file bundle parse failed",
        description: "the .NET single-file bundle manifest did not parse.",
        common_causes: &["truncated bundle", "unsupported bundle version"],
        common_fixes: &["confirm the input is a .NET single-file bundle (major version 1, 2, or 6 and up)"],
        crate_path: "crates/disrobe-binfmt/src/error.rs",
    },
    CodeEntry {
        code: "DR-BINFMT-0067",
        title: "cython extension recovery failed",
        description: "the compiled Cython extension could not be recovered.",
        common_causes: &["not a Cython-built extension", "truncated shared object"],
        common_fixes: &["confirm the input is a Cython-compiled .pyd or .so extension"],
        crate_path: "crates/disrobe-binfmt/src/error.rs",
    },
    CodeEntry {
        code: "DR-BINFMT-0068",
        title: "minidump parse failed",
        description: "the Windows minidump did not parse.",
        common_causes: &["truncated minidump", "missing stream directory"],
        common_fixes: &["confirm the input is a Windows .dmp minidump"],
        crate_path: "crates/disrobe-binfmt/src/error.rs",
    },
];
