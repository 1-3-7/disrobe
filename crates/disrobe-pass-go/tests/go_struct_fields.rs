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

fn recovered_fields(binary: &Path) -> Vec<ReflectField> {
    let bytes: Vec<u8> = std::fs::read(binary).expect("read cross-built binary");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze cross-built binary");
    let record: &GoTypeRef = analysis
        .typemeta
        .types
        .iter()
        .find(|ty: &&GoTypeRef| ty.name.as_deref() == Some("main.Record"))
        .unwrap_or_else(|| {
            let candidates: Vec<&GoTypeRef> = analysis
                .typemeta
                .types
                .iter()
                .filter(|ty: &&GoTypeRef| {
                    ty.name
                        .as_deref()
                        .is_some_and(|name: &str| name.contains("Record"))
                })
                .collect();
            panic!("main.Record must be reachable through typelinks: {candidates:?}")
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
        let recovered: Vec<ReflectField> = recovered_fields(&binary);
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
