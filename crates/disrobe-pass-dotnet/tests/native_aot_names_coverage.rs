#![allow(clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::aot::{AotReport, detect};

fn real_sample() -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(std::env::var_os("DISROBE_AOT_SAMPLE")?);
    std::fs::read(path).ok()
}

fn length_prefixed(image: &[u8], name: &str) -> bool {
    let prefix: u8 = match u8::try_from(name.len() << 1) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut needle: Vec<u8> = Vec::with_capacity(name.len() + 1);
    needle.push(prefix);
    needle.extend_from_slice(name.as_bytes());
    image.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[test]
fn every_name_the_image_still_carries_is_recovered() {
    let Some(image): Option<Vec<u8>> = real_sample() else {
        println!("SKIP: set DISROBE_AOT_SAMPLE to a native aot executable to run this");
        return;
    };
    let report: AotReport = detect(&image);
    let names: &[String] = &report.recovered_names;

    let declared: [&str; 15] = [
        "Widget",
        "IGauge",
        "Thermometer",
        "DisrobeAotProbe",
        "Program",
        "Main",
        "ToString",
        "Read",
        "Serial",
        "Label",
        "calibration",
        "get_Serial",
        "set_Serial",
        "get_Label",
        "set_Label",
    ];

    let mut present_and_recovered: Vec<&str> = Vec::new();
    let mut present_but_missed: Vec<&str> = Vec::new();
    let mut absent_from_image: Vec<&str> = Vec::new();

    for name in declared {
        let in_image: bool = length_prefixed(&image, name);
        let recovered: bool = names.iter().any(|n: &String| n == name);
        if in_image && recovered {
            present_and_recovered.push(name);
        } else if in_image {
            present_but_missed.push(name);
        } else {
            absent_from_image.push(name);
        }
    }

    println!("recovered           {present_and_recovered:?}");
    println!("in image, missed    {present_but_missed:?}");
    println!("absent from image   {absent_from_image:?}");

    assert!(
        present_but_missed.is_empty(),
        "these names are length-prefixed in the image and the reader still failed to surface them, \
         which is a reader gap rather than a trimmed build: {present_but_missed:?}"
    );
    assert!(
        present_and_recovered.len() >= 8,
        "the probe source declares at least eight names the runtime still needs, got {present_and_recovered:?}"
    );
    assert!(
        absent_from_image
            .iter()
            .all(|n: &&str| !length_prefixed(&image, n)),
        "a name counted as absent must really carry no length-prefixed entry"
    );
}
