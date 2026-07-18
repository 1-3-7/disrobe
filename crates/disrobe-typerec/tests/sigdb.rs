#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_typerec::abi::Convention;
use disrobe_typerec::import_map::{ImportMap, ImportRef};
use disrobe_typerec::recover::CIntType;
use disrobe_typerec::sigdb::{Abi, ParamDir, Prototype, ReturnSemantics, SigDb, Ty};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn pointee(ty: &Ty) -> (&Ty, bool) {
    let Ty::Pointer(pointer) = ty else {
        panic!("expected a pointer type, got {ty:?}");
    };
    (pointer.pointee.as_ref(), pointer.is_const)
}

#[test]
fn seed_is_populated_and_every_entry_is_wellformed() {
    let db: SigDb = SigDb::builtin();
    assert!(
        db.len() >= 30,
        "curated seed must carry >=30 prototypes, got {}",
        db.len()
    );
    assert!(!db.is_empty());

    for (key, proto) in db.entries() {
        assert!(!key.library.is_empty(), "empty library key");
        assert!(!key.name.is_empty(), "empty name key");
        assert_eq!(
            proto.calling_convention,
            key.abi.convention(),
            "prototype convention must match its archive abi for {}!{}",
            key.library,
            key.name,
        );
        assert_eq!(proto.param_count(), proto.params.len());
        for param in &proto.params {
            assert!(
                !param.name.is_empty(),
                "param with empty name in {}",
                key.name
            );
            if let Some(count_index) = param.size_relation {
                assert!(
                    count_index < proto.params.len(),
                    "size relation index out of range in {}",
                    key.name,
                );
            }
        }
        if let Some(format_index) = proto.format_param_index {
            assert!(
                proto.varargs,
                "format index without varargs in {}",
                key.name
            );
            assert!(
                format_index < proto.params.len(),
                "format index out of range in {}",
                key.name,
            );
        }
    }
}

#[test]
fn lookup_hits_seed_and_abstains_otherwise() {
    let db: SigDb = SigDb::builtin();
    assert!(db.lookup("libc", "memcpy", Abi::SysV).is_some());
    assert!(
        db.lookup("libc", "totally_not_a_real_symbol", Abi::SysV)
            .is_none()
    );

    assert!(
        db.lookup("kernel32.dll", "ExitProcess", Abi::Win64)
            .is_some()
    );
    assert!(
        db.lookup("KERNEL32.DLL", "ExitProcess", Abi::Win64)
            .is_some()
    );
    assert!(db.lookup("kernel32", "ExitProcess", Abi::Win64).is_some());

    assert!(
        db.lookup("kernel32", "ExitProcess", Abi::SysV).is_none(),
        "a win64 archive entry must not resolve under the sysv abi",
    );
    assert!(
        db.lookup("libc", "ExitProcess", Abi::SysV).is_none(),
        "keys are (library, name); a wrong library must abstain",
    );
}

#[test]
fn ansi_and_wide_variants_resolve_distinctly() {
    let db: SigDb = SigDb::builtin();
    let ansi: &Prototype = db.lookup("kernel32", "CreateFileA", Abi::Win64).unwrap();
    let wide: &Prototype = db.lookup("kernel32", "CreateFileW", Abi::Win64).unwrap();
    assert!(
        db.lookup("kernel32", "CreateFile", Abi::Win64).is_none(),
        "there is no bare CreateFile entry",
    );

    let (ansi_char, _): (&Ty, bool) = pointee(&ansi.params[0].ty);
    let (wide_char, _): (&Ty, bool) = pointee(&wide.params[0].ty);
    assert_eq!(*ansi_char, Ty::Int(CIntType::I8), "ansi name is char*");
    assert_eq!(*wide_char, Ty::Int(CIntType::U16), "wide name is wchar*");
    assert_ne!(ansi, wide);

    let load_a: &Prototype = db.lookup("kernel32", "LoadLibraryA", Abi::Win64).unwrap();
    let load_w: &Prototype = db.lookup("kernel32", "LoadLibraryW", Abi::Win64).unwrap();
    assert_ne!(load_a, load_w);
}

#[test]
fn memcpy_shape_is_exact() {
    let db: SigDb = SigDb::builtin();
    let proto: &Prototype = db.lookup("libc", "memcpy", Abi::SysV).unwrap();

    let [dst, src, n]: &[_; 3] = proto
        .params
        .as_slice()
        .try_into()
        .expect("memcpy has 3 params");

    let (ret_pointee, ret_const): (&Ty, bool) = pointee(&proto.return_type);
    assert_eq!(*ret_pointee, Ty::Void);
    assert!(!ret_const, "the returned void* is not const");

    let (dst_pointee, dst_const): (&Ty, bool) = pointee(&dst.ty);
    assert_eq!(*dst_pointee, Ty::Void);
    assert!(!dst_const);
    assert_eq!(dst.dir, ParamDir::Out);
    assert_eq!(dst.size_relation, Some(2));

    let (src_pointee, src_const): (&Ty, bool) = pointee(&src.ty);
    assert_eq!(*src_pointee, Ty::Void);
    assert!(src_const, "the source is const void*");
    assert_eq!(src.dir, ParamDir::In);
    assert_eq!(
        src.size_relation,
        Some(2),
        "src buffer size relates to the count param n"
    );

    assert_eq!(n.ty, Ty::Int(CIntType::U64), "n is size_t");
    assert_eq!(proto.return_semantics, ReturnSemantics::Plain);
    assert!(!proto.varargs);
}

#[test]
fn printf_is_variadic_with_format_at_index_zero() {
    let db: SigDb = SigDb::builtin();
    let proto: &Prototype = db.lookup("libc", "printf", Abi::SysV).unwrap();
    assert!(proto.varargs);
    assert_eq!(proto.format_param_index, Some(0));
    assert_eq!(proto.params.len(), 1);
    let (fmt_pointee, fmt_const): (&Ty, bool) = pointee(&proto.params[0].ty);
    assert_eq!(*fmt_pointee, Ty::Int(CIntType::I8));
    assert!(fmt_const);
    assert_eq!(proto.return_type, Ty::Int(CIntType::I32));
}

#[test]
fn createfilew_returns_a_nominal_handle_not_a_pointer() {
    let db: SigDb = SigDb::builtin();
    let proto: &Prototype = db.lookup("kernel32", "CreateFileW", Abi::Win64).unwrap();
    assert_eq!(proto.return_type, Ty::Handle("HANDLE"));
    assert!(
        !matches!(proto.return_type, Ty::Pointer(_)),
        "a HANDLE is a distinct nominal type, never void*",
    );
    assert_eq!(proto.return_semantics, ReturnSemantics::InvalidHandleValue);
    let (name_pointee, name_const): (&Ty, bool) = pointee(&proto.params[0].ty);
    assert_eq!(*name_pointee, Ty::Int(CIntType::U16));
    assert!(name_const);
}

#[test]
fn recv_shape_matches_the_winsock_prototype() {
    let db: SigDb = SigDb::builtin();
    let proto: &Prototype = db.lookup("ws2_32", "recv", Abi::Win64).unwrap();
    let [s, buf, len, flags]: &[_; 4] = proto
        .params
        .as_slice()
        .try_into()
        .expect("recv has 4 params");

    assert_eq!(s.ty, Ty::Handle("SOCKET"), "the socket is a nominal handle");
    let (buf_pointee, buf_const): (&Ty, bool) = pointee(&buf.ty);
    assert_eq!(*buf_pointee, Ty::Int(CIntType::I8), "buf is char*");
    assert!(!buf_const);
    assert_eq!(len.ty, Ty::Int(CIntType::I32));
    assert_eq!(flags.ty, Ty::Int(CIntType::I32));
    assert_eq!(proto.return_type, Ty::Int(CIntType::I32));
}

#[test]
fn abi_maps_to_the_recovered_calling_convention() {
    assert_eq!(Abi::SysV.convention(), Convention::SysVAmd64);
    assert_eq!(Abi::Win64.convention(), Convention::Win64);
}

fn find_import<'a>(map: &'a ImportMap, symbol: &str) -> &'a ImportRef {
    map.by_slot_va
        .values()
        .find(|entry: &&ImportRef| entry.name() == Some(symbol))
        .unwrap_or_else(|| panic!("fixture must import {symbol}"))
}

#[test]
fn pe_import_key_resolves_the_seeded_prototype() {
    let bytes: Vec<u8> = fixture("imports_pe.exe");
    let map: ImportMap = ImportMap::from_image(&bytes);
    let db: SigDb = SigDb::builtin();

    for symbol in ["ExitProcess", "GetLastError"] {
        let import: &ImportRef = find_import(&map, symbol);
        let name: &str = import.lookup_key().expect("named import");
        let proto: &Prototype = db
            .lookup(&import.library, name, Abi::Win64)
            .unwrap_or_else(|| panic!("import map key {}!{name} must resolve", import.library));
        assert_eq!(
            Some(proto),
            db.lookup("kernel32", symbol, Abi::Win64),
            "the importmap-keyed lookup must land on the same prototype",
        );
    }

    let exit: &ImportRef = find_import(&map, "ExitProcess");
    let exit_proto: &Prototype = db.lookup(&exit.library, "ExitProcess", Abi::Win64).unwrap();
    assert_eq!(exit_proto.return_type, Ty::Void);
    assert_eq!(exit_proto.params.len(), 1);
}

#[test]
fn elf_import_name_resolves_the_seeded_libc_prototype() {
    let bytes: Vec<u8> = fixture("imports_elf.so");
    let map: ImportMap = ImportMap::from_image(&bytes);
    let db: SigDb = SigDb::builtin();

    let malloc: &ImportRef = find_import(&map, "malloc");
    let name: &str = malloc.lookup_key().expect("named import");
    let proto: &Prototype = db
        .lookup("libc", name, Abi::SysV)
        .expect("the elf dynsym name must key the libc seed");
    assert_eq!(
        proto.return_type,
        db.lookup("libc", "malloc", Abi::SysV).unwrap().return_type
    );
    assert_eq!(proto.return_semantics, ReturnSemantics::NullFailure);
}
