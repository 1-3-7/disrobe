#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_go::{GoAnalysis, GoStructField, GoTypeRef, analyze};

const STRUCT_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"reflect"
)

type Inner struct {
	Code uint32 `json:"code"`
}

type Record struct {
	ID       uint64 `json:"id" db:"primary"`
	Name     string
	secret   int `audit:"hidden"`
	Inner
	Fixed    [3]byte `bin:"raw"`
	Values   []int
	Index    map[string]*Inner `json:"index,omitempty"`
	Send     chan<- Inner
	Callback func(int, string) (bool, error) `call:"handler"`
}

type Marker interface {
	Mark()
}

func (Record) Mark() {}

var sink Marker

func main() {
	sink = Record{}
	t := reflect.TypeOf(Record{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Fprintf(os.Stdout, "%s\t%d\t%s\t%t\t%t\t%s\t%s\n", f.Name, f.Offset, string(f.Tag), f.Anonymous, f.IsExported(), f.Type.String(), f.Type.Kind())
	}
}
"#;

const SCALAR_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"
)

type Scalars struct {
	Bl   bool
	I    int
	I8   int8
	I16  int16
	I32  int32
	I64  int64
	U    uint
	U8   uint8
	U16  uint16
	U32  uint32
	U64  uint64
	Up   uintptr
	F32  float32
	F64  float64
	C64  complex64
	C128 complex128
	Str  string
	Ptr  unsafe.Pointer
}

func (Scalars) Mark() {}

var sink interface{ Mark() }

func main() {
	sink = Scalars{}
	_ = sink
	t := reflect.TypeOf(Scalars{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Fprintf(os.Stdout, "%s\t%d\t%s\t%t\t%t\t%s\t%s\n", f.Name, f.Offset, string(f.Tag), f.Anonymous, f.IsExported(), f.Type.String(), f.Type.Kind())
	}
}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReflectField {
    name: String,
    offset: u64,
    tag: Option<String>,
    embedded: bool,
    exported: bool,
    type_name: String,
    kind: String,
}

fn reflect_truth(dir: &Path) -> Vec<ReflectField> {
    let output: Output = Command::new("go")
        .args(["run", "."])
        .current_dir(dir)
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on")
        .output()
        .expect("run Go 1.26 reflect ground truth");
    assert!(
        output.status.success(),
        "go run reflect ground truth failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("reflect output is UTF-8")
        .lines()
        .map(|line: &str| {
            let columns: Vec<&str> = line.split('\t').collect();
            assert_eq!(columns.len(), 7, "reflect field row: {line:?}");
            ReflectField {
                name: columns[0].to_owned(),
                offset: columns[1].parse().expect("reflect byte offset"),
                tag: (!columns[2].is_empty()).then(|| columns[2].to_owned()),
                embedded: columns[3].parse().expect("reflect anonymous flag"),
                exported: columns[4].parse().expect("reflect exported flag"),
                type_name: columns[5].to_owned(),
                kind: columns[6].to_owned(),
            }
        })
        .collect()
}

fn recovered_fields(binary: &Path, type_name: &str) -> Vec<ReflectField> {
    let bytes: Vec<u8> = std::fs::read(binary).expect("read cross-built binary");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze cross-built binary");
    let record: &GoTypeRef = analysis
        .typemeta
        .types
        .iter()
        .find(|ty: &&GoTypeRef| ty.name.as_deref() == Some(type_name))
        .unwrap_or_else(|| {
            let short: &str = type_name.rsplit('.').next().unwrap_or(type_name);
            let candidates: Vec<&GoTypeRef> = analysis
                .typemeta
                .types
                .iter()
                .filter(|ty: &&GoTypeRef| {
                    ty.name
                        .as_deref()
                        .is_some_and(|name: &str| name.contains(short))
                })
                .collect();
            panic!("{type_name} must be reachable through typelinks: {candidates:?}")
        });
    assert!(
        !record.fields_rejected,
        "valid Go 1.26 StructType metadata must not carry the rejection marker"
    );
    record
        .fields
        .iter()
        .map(|field: &GoStructField| ReflectField {
            name: field.name.clone(),
            offset: field.offset,
            tag: field.tag.clone(),
            embedded: field.embedded,
            exported: field.exported,
            type_name: field.type_name.clone(),
            kind: field.kind_label.clone(),
        })
        .collect()
}

#[test]
fn struct_fields_match_reflect_across_go126_cross_builds() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("struct_fields");
    common::write_module(&scratch, "disrobe.example/structfields", STRUCT_SOURCE);
    let truth: Vec<ReflectField> = reflect_truth(scratch.path());
    assert_eq!(
        truth.len(),
        9,
        "the reflect probe must exercise nine fields"
    );

    let targets: [(&str, &str, &str); 2] = [
        ("record_windows_amd64.exe", "windows", "amd64"),
        ("record_linux_amd64", "linux", "amd64"),
    ];
    for (name, goos, goarch) in targets {
        let binary: PathBuf = common::go_build_cross(&scratch, name, goos, goarch, &[])
            .unwrap_or_else(|| panic!("go1.26 cross-build failed for {goos}/{goarch}"));
        let recovered: Vec<ReflectField> = recovered_fields(&binary, "main.Record");
        let hit: usize = truth
            .iter()
            .zip(&recovered)
            .filter(|(expected, actual): &(&ReflectField, &ReflectField)| expected == actual)
            .count();
        eprintln!(
            "go1.26 {goos}/{goarch}: struct-field recovery {hit}/{}; recovered={recovered:?}",
            truth.len()
        );
        assert_eq!(
            recovered, truth,
            "struct fields must match live reflect output for {goos}/{goarch}"
        );
    }
}

#[test]
fn scalar_widths_and_signedness_match_reflect_across_go126_cross_builds() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("scalar_widths");
    common::write_module(&scratch, "disrobe.example/scalarwidths", SCALAR_SOURCE);
    let truth: Vec<ReflectField> = reflect_truth(scratch.path());
    assert_eq!(
        truth.len(),
        18,
        "the width probe must exercise eighteen scalar fields"
    );
    let kinds: Vec<&str> = truth
        .iter()
        .map(|f: &ReflectField| f.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "bool",
            "int",
            "int8",
            "int16",
            "int32",
            "int64",
            "uint",
            "uint8",
            "uint16",
            "uint32",
            "uint64",
            "uintptr",
            "float32",
            "float64",
            "complex64",
            "complex128",
            "string",
            "unsafe.Pointer",
        ],
        "reflect must report every scalar width and signedness distinctly"
    );

    let targets: [(&str, &str, &str); 3] = [
        ("scalar_windows_amd64.exe", "windows", "amd64"),
        ("scalar_linux_amd64", "linux", "amd64"),
        ("scalar_linux_386", "linux", "386"),
    ];
    for (name, goos, goarch) in targets {
        let binary: PathBuf = common::go_build_cross(&scratch, name, goos, goarch, &[])
            .unwrap_or_else(|| panic!("go1.26 cross-build failed for {goos}/{goarch}"));
        let recovered: Vec<ReflectField> = recovered_fields(&binary, "main.Scalars");
        let recovered_widths: Vec<(String, String)> = recovered
            .iter()
            .map(|f: &ReflectField| (f.type_name.clone(), f.kind.clone()))
            .collect();
        let truth_widths: Vec<(String, String)> = truth
            .iter()
            .map(|f: &ReflectField| (f.type_name.clone(), f.kind.clone()))
            .collect();
        eprintln!("go1.26 {goos}/{goarch}: scalar-width recovery {recovered_widths:?}");
        assert_eq!(
            recovered_widths, truth_widths,
            "scalar width and signedness must match live reflect output for {goos}/{goarch}"
        );
    }
}
