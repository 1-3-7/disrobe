#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_dotnet::metadata::{MetadataRoot, RuntimeLabel, parse_metadata_root};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

use crate::common::synth_minimal_dotnet_pe;

#[test]
fn metadata_root_labels_dotnet_4() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let pe: PeImage = parse(&img).expect("pe");
    let clr: ClrHeader = parse_clr_header(&img, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&img, &pe, &clr).expect("root");
    assert_eq!(root.runtime_label(), RuntimeLabel::NetFramework4);
}

#[test]
fn metadata_root_labels_dotnet_8() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v8.0.0");
    let pe: PeImage = parse(&img).expect("pe");
    let clr: ClrHeader = parse_clr_header(&img, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&img, &pe, &clr).expect("root");
    assert_eq!(root.runtime_label(), RuntimeLabel::Net8);
}

#[test]
fn metadata_root_labels_dotnet_9() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v9.0.0");
    let pe: PeImage = parse(&img).expect("pe");
    let clr: ClrHeader = parse_clr_header(&img, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&img, &pe, &clr).expect("root");
    assert_eq!(root.runtime_label(), RuntimeLabel::Net9);
}

#[test]
fn metadata_root_labels_dotnet_10() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v10.0.0");
    let pe: PeImage = parse(&img).expect("pe");
    let clr: ClrHeader = parse_clr_header(&img, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(&img, &pe, &clr).expect("root");
    assert_eq!(root.runtime_label(), RuntimeLabel::Net10OrLater);
}
