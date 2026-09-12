use std::path::PathBuf;

use disrobe_pass_swift_objc::macho::{self, CpuKind, FatArchEntry, MachoKind, ParsedSlice};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::ObjcInterface;
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
use disrobe_pass_swift_objc::swift_reflect::SwiftTypeReflection;

fn x86_64_slice(bytes: &[u8]) -> Option<(Vec<u8>, ParsedSlice)> {
    match macho::detect_magic(bytes)? {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes).ok()?;
            let entry: &FatArchEntry = entries
                .iter()
                .find(|e: &&FatArchEntry| matches!(e.cpu, CpuKind::X86_64))
                .or_else(|| entries.first())?;
            let inner: &[u8] = macho::slice_bytes(bytes, entry)?;
            let parsed: ParsedSlice = macho::parse_slice(inner).ok()?;
            Some((inner.to_vec(), parsed))
        }
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(bytes).ok()?;
            Some((bytes.to_vec(), parsed))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path: PathBuf = PathBuf::from(
        args.get(1)
            .map_or("corpus/mobile/macho-mac/codesign", |s: &String| s.as_str()),
    );
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
        eprintln!("could not read {}", path.display());
        return;
    };
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = x86_64_slice(&bytes) else {
        eprintln!("not a mach-o");
        return;
    };

    let objc: ObjcClassDump = objc::class_dump(&slice, &parsed);
    println!(
        "=== ObjC: {} interfaces recovered ===",
        objc.interfaces.len()
    );
    for iface in objc.interfaces.iter().take(2) {
        print!("{}", ObjcInterface::render(iface));
        println!("---");
    }

    let swift: SwiftClassDump = swift::class_dump(&slice, &parsed);
    println!(
        "\n=== Swift: {} reflected types, {} fields total ===",
        swift.reflected_types.len(),
        swift
            .reflected_types
            .iter()
            .map(|t: &SwiftTypeReflection| t.fields.len())
            .sum::<usize>()
    );
    for ty in swift
        .reflected_types
        .iter()
        .filter(|t: &&SwiftTypeReflection| t.fields.len() >= 2)
        .take(3)
    {
        print!("{}", SwiftTypeReflection::render(ty));
        println!("---");
    }

    let td = &swift.type_dump;
    println!(
        "\n=== Swift type dump: {} nominal types, {} protocols, {} conformances, {} assoc records ===",
        td.nominal_types.len(),
        td.protocols.len(),
        td.conformances.len(),
        td.associated_types.len()
    );
    print!("{}", td.render());
}
