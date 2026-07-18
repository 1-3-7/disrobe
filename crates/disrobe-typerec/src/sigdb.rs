use std::collections::BTreeMap;

use crate::abi::Convention;
use crate::lattice::Width;
use crate::recover::CIntType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerTy {
    pub pointee: Box<Ty>,
    pub is_const: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    Void,
    Int(CIntType),
    Float(Width),
    Pointer(PointerTy),
    Handle(&'static str),
    Struct(&'static str),
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamDir {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: &'static str,
    pub ty: Ty,
    pub dir: ParamDir,
    pub optional: bool,
    pub size_relation: Option<usize>,
}

impl Param {
    const fn opt(mut self) -> Self {
        self.optional = true;
        self
    }

    const fn sized_by(mut self, count_param: usize) -> Self {
        self.size_relation = Some(count_param);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReturnSemantics {
    Plain,
    BoolFailure,
    HResult,
    ErrnoReturn,
    NullFailure,
    InvalidHandleValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Abi {
    SysV,
    Win64,
}

impl Abi {
    #[must_use]
    pub const fn convention(self) -> Convention {
        match self {
            Self::SysV => Convention::SysVAmd64,
            Self::Win64 => Convention::Win64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    pub calling_convention: Convention,
    pub return_type: Ty,
    pub params: Vec<Param>,
    pub varargs: bool,
    pub format_param_index: Option<usize>,
    pub return_semantics: ReturnSemantics,
}

impl Prototype {
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.params.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigKey {
    pub abi: Abi,
    pub library: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigDb {
    entries: BTreeMap<SigKey, Prototype>,
}

impl Default for SigDb {
    fn default() -> Self {
        Self::builtin()
    }
}

impl SigDb {
    #[must_use]
    pub fn builtin() -> Self {
        let mut entries: BTreeMap<SigKey, Prototype> = BTreeMap::new();
        insert_all(&mut entries, "libc", Abi::SysV, libc_entries());
        insert_all(&mut entries, "kernel32", Abi::Win64, kernel32_entries());
        insert_all(&mut entries, "ws2_32", Abi::Win64, ws2_32_entries());
        Self { entries }
    }

    #[must_use]
    pub fn lookup(&self, library: &str, name: &str, abi: Abi) -> Option<&Prototype> {
        let key: SigKey = SigKey {
            abi,
            library: normalize_library(library),
            name: name.to_owned(),
        };
        self.entries.get(&key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&SigKey, &Prototype)> {
        self.entries.iter()
    }
}

fn normalize_library(raw: &str) -> String {
    let lower: String = raw.trim().to_ascii_lowercase();
    if let Some(base) = lower.strip_suffix(".dll") {
        return base.to_owned();
    }
    if let Some(base) = lower.strip_suffix(".exe") {
        return base.to_owned();
    }
    if let Some(index) = lower.find(".so") {
        let tail: &str = &lower[index + 3..];
        if tail.is_empty() || tail.starts_with('.') {
            return lower[..index].to_owned();
        }
    }
    lower
}

fn insert_all(
    entries: &mut BTreeMap<SigKey, Prototype>,
    library: &str,
    abi: Abi,
    list: Vec<(&'static str, Prototype)>,
) {
    let normalized: String = normalize_library(library);
    for (name, mut prototype) in list {
        prototype.calling_convention = abi.convention();
        entries.insert(
            SigKey {
                abi,
                library: normalized.clone(),
                name: name.to_owned(),
            },
            prototype,
        );
    }
}

const fn int(c: CIntType) -> Ty {
    Ty::Int(c)
}

const fn handle(name: &'static str) -> Ty {
    Ty::Handle(name)
}

const fn opaque(name: &'static str) -> Ty {
    Ty::Struct(name)
}

fn ptr_to(pointee: Ty) -> Ty {
    Ty::Pointer(PointerTy {
        pointee: Box::new(pointee),
        is_const: false,
    })
}

fn const_ptr_to(pointee: Ty) -> Ty {
    Ty::Pointer(PointerTy {
        pointee: Box::new(pointee),
        is_const: true,
    })
}

fn void_ptr() -> Ty {
    ptr_to(Ty::Void)
}

fn const_void_ptr() -> Ty {
    const_ptr_to(Ty::Void)
}

fn char_ptr() -> Ty {
    ptr_to(int(CIntType::I8))
}

fn const_char_ptr() -> Ty {
    const_ptr_to(int(CIntType::I8))
}

fn const_wchar_ptr() -> Ty {
    const_ptr_to(int(CIntType::U16))
}

const fn param(name: &'static str, ty: Ty, dir: ParamDir) -> Param {
    Param {
        name,
        ty,
        dir,
        optional: false,
        size_relation: None,
    }
}

const fn proto(
    return_type: Ty,
    params: Vec<Param>,
    return_semantics: ReturnSemantics,
) -> Prototype {
    Prototype {
        calling_convention: Convention::Unknown,
        return_type,
        params,
        varargs: false,
        format_param_index: None,
        return_semantics,
    }
}

const fn variadic_proto(
    return_type: Ty,
    params: Vec<Param>,
    format_param_index: Option<usize>,
    return_semantics: ReturnSemantics,
) -> Prototype {
    Prototype {
        calling_convention: Convention::Unknown,
        return_type,
        params,
        varargs: true,
        format_param_index,
        return_semantics,
    }
}

fn libc_entries() -> Vec<(&'static str, Prototype)> {
    use CIntType::{I32, I64, U64};
    use ParamDir::{In, InOut, Out};
    use ReturnSemantics::{ErrnoReturn, NullFailure, Plain};
    vec![
        (
            "memcpy",
            proto(
                void_ptr(),
                vec![
                    param("dst", void_ptr(), Out).sized_by(2),
                    param("src", const_void_ptr(), In).sized_by(2),
                    param("n", int(U64), In),
                ],
                Plain,
            ),
        ),
        (
            "memmove",
            proto(
                void_ptr(),
                vec![
                    param("dst", void_ptr(), Out).sized_by(2),
                    param("src", const_void_ptr(), In).sized_by(2),
                    param("n", int(U64), In),
                ],
                Plain,
            ),
        ),
        (
            "memset",
            proto(
                void_ptr(),
                vec![
                    param("s", void_ptr(), Out).sized_by(2),
                    param("c", int(I32), In),
                    param("n", int(U64), In),
                ],
                Plain,
            ),
        ),
        (
            "strlen",
            proto(int(U64), vec![param("s", const_char_ptr(), In)], Plain),
        ),
        (
            "strcpy",
            proto(
                char_ptr(),
                vec![
                    param("dst", char_ptr(), Out),
                    param("src", const_char_ptr(), In),
                ],
                Plain,
            ),
        ),
        (
            "strncpy",
            proto(
                char_ptr(),
                vec![
                    param("dst", char_ptr(), Out).sized_by(2),
                    param("src", const_char_ptr(), In),
                    param("n", int(U64), In),
                ],
                Plain,
            ),
        ),
        (
            "strcmp",
            proto(
                int(I32),
                vec![
                    param("a", const_char_ptr(), In),
                    param("b", const_char_ptr(), In),
                ],
                Plain,
            ),
        ),
        (
            "malloc",
            proto(void_ptr(), vec![param("size", int(U64), In)], NullFailure),
        ),
        (
            "calloc",
            proto(
                void_ptr(),
                vec![param("nmemb", int(U64), In), param("size", int(U64), In)],
                NullFailure,
            ),
        ),
        (
            "realloc",
            proto(
                void_ptr(),
                vec![
                    param("ptr", void_ptr(), In).opt(),
                    param("size", int(U64), In),
                ],
                NullFailure,
            ),
        ),
        (
            "free",
            proto(Ty::Void, vec![param("ptr", void_ptr(), In)], Plain),
        ),
        (
            "printf",
            variadic_proto(
                int(I32),
                vec![param("format", const_char_ptr(), In)],
                Some(0),
                Plain,
            ),
        ),
        (
            "fprintf",
            variadic_proto(
                int(I32),
                vec![
                    param("stream", ptr_to(opaque("FILE")), InOut),
                    param("format", const_char_ptr(), In),
                ],
                Some(1),
                Plain,
            ),
        ),
        (
            "fopen",
            proto(
                ptr_to(opaque("FILE")),
                vec![
                    param("path", const_char_ptr(), In),
                    param("mode", const_char_ptr(), In),
                ],
                NullFailure,
            ),
        ),
        (
            "fwrite",
            proto(
                int(U64),
                vec![
                    param("ptr", const_void_ptr(), In),
                    param("size", int(U64), In),
                    param("nmemb", int(U64), In),
                    param("stream", ptr_to(opaque("FILE")), InOut),
                ],
                Plain,
            ),
        ),
        (
            "fread",
            proto(
                int(U64),
                vec![
                    param("ptr", void_ptr(), Out),
                    param("size", int(U64), In),
                    param("nmemb", int(U64), In),
                    param("stream", ptr_to(opaque("FILE")), InOut),
                ],
                Plain,
            ),
        ),
        (
            "fclose",
            proto(
                int(I32),
                vec![param("stream", ptr_to(opaque("FILE")), InOut)],
                ErrnoReturn,
            ),
        ),
        (
            "read",
            proto(
                int(I64),
                vec![
                    param("fd", int(I32), In),
                    param("buf", void_ptr(), Out).sized_by(2),
                    param("count", int(U64), In),
                ],
                ErrnoReturn,
            ),
        ),
        (
            "write",
            proto(
                int(I64),
                vec![
                    param("fd", int(I32), In),
                    param("buf", const_void_ptr(), In).sized_by(2),
                    param("count", int(U64), In),
                ],
                ErrnoReturn,
            ),
        ),
        (
            "open",
            variadic_proto(
                int(I32),
                vec![
                    param("path", const_char_ptr(), In),
                    param("flags", int(I32), In),
                ],
                None,
                ErrnoReturn,
            ),
        ),
        (
            "close",
            proto(int(I32), vec![param("fd", int(I32), In)], ErrnoReturn),
        ),
    ]
}

fn create_file(name_param: Ty) -> Prototype {
    use CIntType::U32;
    use ParamDir::In;
    proto(
        handle("HANDLE"),
        vec![
            param("lpFileName", name_param, In),
            param("dwDesiredAccess", int(U32), In),
            param("dwShareMode", int(U32), In),
            param(
                "lpSecurityAttributes",
                ptr_to(opaque("SECURITY_ATTRIBUTES")),
                In,
            )
            .opt(),
            param("dwCreationDisposition", int(U32), In),
            param("dwFlagsAndAttributes", int(U32), In),
            param("hTemplateFile", handle("HANDLE"), In).opt(),
        ],
        ReturnSemantics::InvalidHandleValue,
    )
}

fn read_write_file(buffer: Ty, count_dir: ParamDir) -> Prototype {
    use CIntType::U32;
    use ParamDir::{In, InOut, Out};
    proto(
        int(CIntType::I32),
        vec![
            param("hFile", handle("HANDLE"), In),
            param("lpBuffer", buffer, count_dir).sized_by(2),
            param("nNumberOfBytes", int(U32), In),
            param("lpNumberOfBytesTransferred", ptr_to(int(U32)), Out).opt(),
            param("lpOverlapped", ptr_to(opaque("OVERLAPPED")), InOut).opt(),
        ],
        ReturnSemantics::BoolFailure,
    )
}

fn kernel32_entries() -> Vec<(&'static str, Prototype)> {
    use CIntType::{U32, U64};
    use ParamDir::{In, Out};
    use ReturnSemantics::{BoolFailure, NullFailure, Plain};
    vec![
        ("CreateFileA", create_file(const_char_ptr())),
        ("CreateFileW", create_file(const_wchar_ptr())),
        ("ReadFile", read_write_file(void_ptr(), Out)),
        ("WriteFile", read_write_file(const_void_ptr(), In)),
        (
            "CloseHandle",
            proto(
                int(CIntType::I32),
                vec![param("hObject", handle("HANDLE"), In)],
                BoolFailure,
            ),
        ),
        (
            "HeapAlloc",
            proto(
                void_ptr(),
                vec![
                    param("hHeap", handle("HANDLE"), In),
                    param("dwFlags", int(U32), In),
                    param("dwBytes", int(U64), In),
                ],
                NullFailure,
            ),
        ),
        (
            "HeapFree",
            proto(
                int(CIntType::I32),
                vec![
                    param("hHeap", handle("HANDLE"), In),
                    param("dwFlags", int(U32), In),
                    param("lpMem", void_ptr(), In),
                ],
                BoolFailure,
            ),
        ),
        ("GetLastError", proto(int(U32), vec![], Plain)),
        ("GetTickCount", proto(int(U32), vec![], Plain)),
        (
            "VirtualAlloc",
            proto(
                void_ptr(),
                vec![
                    param("lpAddress", void_ptr(), In).opt(),
                    param("dwSize", int(U64), In),
                    param("flAllocationType", int(U32), In),
                    param("flProtect", int(U32), In),
                ],
                NullFailure,
            ),
        ),
        (
            "GetProcAddress",
            proto(
                Ty::Code,
                vec![
                    param("hModule", handle("HMODULE"), In),
                    param("lpProcName", const_char_ptr(), In),
                ],
                NullFailure,
            ),
        ),
        (
            "LoadLibraryA",
            proto(
                handle("HMODULE"),
                vec![param("lpLibFileName", const_char_ptr(), In)],
                NullFailure,
            ),
        ),
        (
            "LoadLibraryW",
            proto(
                handle("HMODULE"),
                vec![param("lpLibFileName", const_wchar_ptr(), In)],
                NullFailure,
            ),
        ),
        (
            "GetModuleHandleA",
            proto(
                handle("HMODULE"),
                vec![param("lpModuleName", const_char_ptr(), In).opt()],
                NullFailure,
            ),
        ),
        (
            "ExitProcess",
            proto(Ty::Void, vec![param("uExitCode", int(U32), In)], Plain),
        ),
    ]
}

fn ws2_32_entries() -> Vec<(&'static str, Prototype)> {
    use CIntType::I32;
    use ParamDir::{In, Out};
    use ReturnSemantics::{ErrnoReturn, InvalidHandleValue};
    vec![
        (
            "recv",
            proto(
                int(I32),
                vec![
                    param("s", handle("SOCKET"), In),
                    param("buf", char_ptr(), Out).sized_by(2),
                    param("len", int(I32), In),
                    param("flags", int(I32), In),
                ],
                ErrnoReturn,
            ),
        ),
        (
            "send",
            proto(
                int(I32),
                vec![
                    param("s", handle("SOCKET"), In),
                    param("buf", const_char_ptr(), In).sized_by(2),
                    param("len", int(I32), In),
                    param("flags", int(I32), In),
                ],
                ErrnoReturn,
            ),
        ),
        (
            "socket",
            proto(
                handle("SOCKET"),
                vec![
                    param("af", int(I32), In),
                    param("type", int(I32), In),
                    param("protocol", int(I32), In),
                ],
                InvalidHandleValue,
            ),
        ),
        (
            "connect",
            proto(
                int(I32),
                vec![
                    param("s", handle("SOCKET"), In),
                    param("name", const_ptr_to(opaque("sockaddr")), In),
                    param("namelen", int(I32), In),
                ],
                ErrnoReturn,
            ),
        ),
    ]
}
