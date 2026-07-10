#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;

use disrobe_pass_go::{
    Endian, GoAnalysis, GoImage, GoItab, GoTypeRef, ModuledataSource, PclntabVersion, analyze,
    locate_pclntab,
};

const BIGENDIAN_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"sort"
)

type Shape interface{ Area() float64 }
type Rect struct{ W, H float64 }

func (r Rect) Area() float64 { return r.W * r.H }

type Circle struct{ R float64 }

func (c Circle) Area() float64 { return 3.14159 * c.R * c.R }

type Widget struct {
	Name  string
	Sizes []int
}

func (w *Widget) Describe() string { return fmt.Sprintf("%s:%v", w.Name, w.Sizes) }

func main() {
	shapes := []Shape{Rect{3, 4}, Circle{2}}
	total := 0.0
	for _, s := range shapes {
		total += s.Area()
	}
	w := &Widget{Name: "gizmo", Sizes: []int{5, 1, 3}}
	sort.Ints(w.Sizes)
	fmt.Fprintln(os.Stdout, w.Describe(), total)
}
"#;

fn recovered_type_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .map(common::normalize_type_name)
        .collect()
}

fn recovered_itab_pairs(analysis: &GoAnalysis) -> BTreeSet<(String, String)> {
    analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| {
            Some((
                common::normalize_type_name(i.concrete_name.as_deref()?),
                common::normalize_type_name(i.interface_name.as_deref()?),
            ))
        })
        .collect()
}

#[test]
fn big_endian_s390x_reports_big_endian_and_go120_version() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("s390x_ver");
    common::write_module(&scratch, "disrobe.example/bigendian", BIGENDIAN_SOURCE);
    let Some(binary): Option<std::path::PathBuf> =
        common::go_build_cross(&scratch, "app", "linux", "s390x", &[])
    else {
        panic!("cross go build linux/s390x failed; the big-endian recovery oracle cannot run");
    };
    let bytes: Vec<u8> = std::fs::read(&binary).expect("read s390x build");

    let image: GoImage<'_> = GoImage::parse(&bytes).expect("parse s390x elf");
    assert_eq!(
        image.endian,
        Endian::Big,
        "a linux/s390x go binary is a big-endian ELF image"
    );
    assert_eq!(image.ptr_size, 8, "s390x is a 64-bit target");

    let located = locate_pclntab(&image).expect("locate pclntab on big-endian image");
    assert_eq!(
        located.header.version,
        PclntabVersion::Go120,
        "go1.26 emits the 0xfffffff1 pclntab magic stored big-endian on s390x; the magic search \
         must read it in image byte order and not fall through to the structural scan, which \
         mislabels the layout as go1.18"
    );
}

#[test]
fn big_endian_s390x_stripped_recovers_types_and_itabs_via_backsearch() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("s390x_recover");
    common::write_module(&scratch, "disrobe.example/bigendian", BIGENDIAN_SOURCE);
    let Some(normal): Option<std::path::PathBuf> =
        common::go_build_cross(&scratch, "app", "linux", "s390x", &[])
    else {
        panic!("cross go build linux/s390x failed; the big-endian recovery oracle cannot run");
    };
    let Some(stripped): Option<std::path::PathBuf> = common::go_build_cross(
        &scratch,
        "app_stripped",
        "linux",
        "s390x",
        &["-ldflags", "-s -w"],
    ) else {
        panic!("cross go build -s -w linux/s390x failed; the recovery oracle cannot run");
    };

    let eq_truth: BTreeSet<String> = common::nm_eq_type_names(&normal)
        .expect("go tool nm type:.eq must produce the big-endian type oracle")
        .into_iter()
        .filter(|n: &String| n.contains('.'))
        .collect();
    assert!(
        eq_truth.len() > 40,
        "the s390x build emits dozens of named type equality routines; got {}",
        eq_truth.len()
    );
    let itab_truth: BTreeSet<(String, String)> =
        common::nm_itab_pairs(&normal).expect("go tool nm go:itab must produce the itab oracle");
    assert!(
        !itab_truth.is_empty(),
        "the s390x build stores interface values, so it emits go:itab.* symbols"
    );

    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped s390x build");
    let analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped s390x build");

    assert_eq!(
        analysis.moduledata.via,
        ModuledataSource::PclntabBacksearch,
        "a -s -w big-endian binary has no runtime.firstmoduledata symbol; moduledata must be \
         recovered by the pclntab back-search reading candidate pointers in big-endian order"
    );
    assert_ne!(
        analysis.moduledata.typelinks_va, 0,
        "the back-search must land a moduledata whose typelinks slice is populated"
    );

    let recovered_types: BTreeSet<String> = recovered_type_names(&analysis);
    let eq_hit: usize = eq_truth
        .iter()
        .filter(|n| recovered_types.contains(*n))
        .count();
    let eq_total: usize = eq_truth.len();
    #[allow(clippy::cast_precision_loss)]
    let eq_ratio: f64 = eq_hit as f64 / eq_total.max(1) as f64;
    let eq_missing: Vec<&String> = eq_truth
        .iter()
        .filter(|n| !recovered_types.contains(*n))
        .collect();
    eprintln!(
        "s390x stripped (big-endian elf): type-eq recovery {eq_hit}/{eq_total} = {eq_ratio:.4}; missing={eq_missing:?}"
    );
    assert!(
        eq_ratio >= 1.0,
        "stripped big-endian type-name recovery vs the `go tool nm` type:.eq oracle must be 100% \
         once the moduledata back-search is endian-aware: {eq_hit}/{eq_total} = {eq_ratio:.4}; \
         missing {eq_missing:?}"
    );
    let user_eq: BTreeSet<&String> = eq_truth
        .iter()
        .filter(|n: &&String| n.starts_with("main."))
        .collect();
    assert!(
        user_eq.contains(&"main.Rect".to_owned()),
        "the type:.eq oracle must include the user type main.Rect; got {user_eq:?}"
    );
    for name in &user_eq {
        assert!(
            recovered_types.contains(*name),
            "user type {name} from the type:.eq oracle must be recovered from the stripped \
             big-endian binary; recovered {} names",
            recovered_types.len()
        );
    }

    let recovered_itabs: BTreeSet<(String, String)> = recovered_itab_pairs(&analysis);
    let itab_hit: usize = itab_truth
        .iter()
        .filter(|p| recovered_itabs.contains(*p))
        .count();
    let itab_total: usize = itab_truth.len();
    #[allow(clippy::cast_precision_loss)]
    let itab_ratio: f64 = itab_hit as f64 / itab_total.max(1) as f64;
    let itab_missing: Vec<&(String, String)> = itab_truth
        .iter()
        .filter(|p| !recovered_itabs.contains(*p))
        .collect();
    eprintln!(
        "s390x stripped (big-endian elf): itab recovery {itab_hit}/{itab_total} = {itab_ratio:.4}; missing={itab_missing:?}"
    );
    assert!(
        itab_ratio >= 1.0,
        "stripped big-endian itab recovery vs the `go tool nm` go:itab oracle must be 100%: \
         {itab_hit}/{itab_total} = {itab_ratio:.4}; missing {itab_missing:?}"
    );
}
