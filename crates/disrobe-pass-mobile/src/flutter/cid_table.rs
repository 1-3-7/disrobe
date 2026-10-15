use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCidTable {
    pub version_hash: String,
    pub dart_sdk: String,
    pub predefined_count: u16,
}

pub const DART_3_12_VERSION_HASH: &str = "ace654289f5abc240509fc941453ebc5";

pub const DART_3_12_SDK: &str = "3.12.2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartClassIdTable {
    pub internal_only: &'static [&'static str],
    pub strings: &'static [&'static str],
}

const LEADING_CIDS: &[&str] = &[
    "Illegal",
    "NativePointer",
    "FreeListElement",
    "ForwardingCorpse",
    "Object",
];

const INTERNAL_ONLY_CIDS_3_3: &[&str] = &[
    "Class",
    "PatchClass",
    "Function",
    "TypeParameters",
    "ClosureData",
    "FfiTrampolineData",
    "Field",
    "Script",
    "Library",
    "Namespace",
    "KernelProgramInfo",
    "WeakSerializationReference",
    "WeakArray",
    "Code",
    "Instructions",
    "InstructionsSection",
    "InstructionsTable",
    "ObjectPool",
    "PcDescriptors",
    "CodeSourceMap",
    "CompressedStackMaps",
    "LocalVarDescriptors",
    "ExceptionHandlers",
    "Context",
    "ContextScope",
    "Sentinel",
    "SingleTargetCache",
    "UnlinkedCall",
    "MonomorphicSmiableCall",
    "CallSiteData",
    "ICData",
    "MegamorphicCache",
    "SubtypeTestCache",
    "LoadingUnit",
    "Error",
    "ApiError",
    "LanguageError",
    "UnhandledException",
    "UnwindError",
];

const INTERNAL_ONLY_CIDS_3_6: &[&str] = &[
    "Class",
    "PatchClass",
    "Function",
    "TypeParameters",
    "ClosureData",
    "FfiTrampolineData",
    "Field",
    "Script",
    "Library",
    "Namespace",
    "KernelProgramInfo",
    "WeakSerializationReference",
    "WeakArray",
    "Code",
    "Bytecode",
    "Instructions",
    "InstructionsSection",
    "InstructionsTable",
    "ObjectPool",
    "PcDescriptors",
    "CodeSourceMap",
    "CompressedStackMaps",
    "LocalVarDescriptors",
    "ExceptionHandlers",
    "Context",
    "ContextScope",
    "Sentinel",
    "SingleTargetCache",
    "UnlinkedCall",
    "MonomorphicSmiableCall",
    "CallSiteData",
    "ICData",
    "MegamorphicCache",
    "SubtypeTestCache",
    "LoadingUnit",
    "Error",
    "ApiError",
    "LanguageError",
    "UnhandledException",
    "UnwindError",
];

const INTERNAL_ONLY_CIDS_3_9: &[&str] = &[
    "Class",
    "PatchClass",
    "Function",
    "TypeParameters",
    "ClosureData",
    "FfiTrampolineData",
    "Field",
    "Script",
    "Library",
    "Namespace",
    "KernelProgramInfo",
    "WeakSerializationReference",
    "WeakArray",
    "Code",
    "Bytecode",
    "Instructions",
    "InstructionsSection",
    "InstructionsTable",
    "ObjectPool",
    "PcDescriptors",
    "CodeSourceMap",
    "CompressedStackMaps",
    "LocalVarDescriptors",
    "ExceptionHandlers",
    "Context",
    "ContextScope",
    "Sentinel",
    "SingleTargetCache",
    "MonomorphicSmiableCall",
    "CallSiteData",
    "UnlinkedCall",
    "ICData",
    "MegamorphicCache",
    "SubtypeTestCache",
    "LoadingUnit",
    "Error",
    "ApiError",
    "LanguageError",
    "UnhandledException",
    "UnwindError",
];

const INSTANCE_SINGLETON_CIDS: &[&str] = &[
    "Instance",
    "LibraryPrefix",
    "TypeArguments",
    "AbstractType",
    "Type",
    "FunctionType",
    "RecordType",
    "TypeParameter",
    "FinalizerBase",
    "Finalizer",
    "NativeFinalizer",
    "FinalizerEntry",
    "Closure",
    "Number",
    "Integer",
    "Smi",
    "Mint",
    "Double",
    "Bool",
    "Float32x4",
    "Int32x4",
    "Float64x2",
    "Record",
    "TypedDataBase",
    "TypedData",
    "ExternalTypedData",
    "TypedDataView",
    "Pointer",
    "DynamicLibrary",
    "Capability",
    "ReceivePort",
    "SendPort",
    "StackTrace",
    "SuspendState",
    "RegExp",
    "WeakProperty",
    "WeakReference",
    "MirrorReference",
    "FutureOr",
    "UserTag",
    "TransferableTypedData",
];

const MAP_SET_ARRAY_CIDS: &[&str] = &[
    "Map",
    "ConstMap",
    "Set",
    "ConstSet",
    "Array",
    "ImmutableArray",
    "GrowableObjectArray",
];

const STRING_CIDS_3_3: &[&str] = &[
    "String",
    "OneByteString",
    "TwoByteString",
    "ExternalOneByteString",
    "ExternalTwoByteString",
];

const STRING_CIDS: &[&str] = &["String", "OneByteString", "TwoByteString"];

const FFI_CIDS: &[&str] = &[
    "FfiNativeFunction",
    "FfiInt8",
    "FfiInt16",
    "FfiInt32",
    "FfiInt64",
    "FfiUint8",
    "FfiUint16",
    "FfiUint32",
    "FfiUint64",
    "FfiFloat",
    "FfiDouble",
    "FfiVoid",
    "FfiHandle",
    "FfiBool",
    "FfiNativeType",
    "FfiStruct",
];

const TYPED_DATA_CIDS: &[&str] = &[
    "TypedDataInt8Array",
    "TypedDataInt8ArrayView",
    "ExternalTypedDataInt8Array",
    "UnmodifiableTypedDataInt8ArrayView",
    "TypedDataUint8Array",
    "TypedDataUint8ArrayView",
    "ExternalTypedDataUint8Array",
    "UnmodifiableTypedDataUint8ArrayView",
    "TypedDataUint8ClampedArray",
    "TypedDataUint8ClampedArrayView",
    "ExternalTypedDataUint8ClampedArray",
    "UnmodifiableTypedDataUint8ClampedArrayView",
    "TypedDataInt16Array",
    "TypedDataInt16ArrayView",
    "ExternalTypedDataInt16Array",
    "UnmodifiableTypedDataInt16ArrayView",
    "TypedDataUint16Array",
    "TypedDataUint16ArrayView",
    "ExternalTypedDataUint16Array",
    "UnmodifiableTypedDataUint16ArrayView",
    "TypedDataInt32Array",
    "TypedDataInt32ArrayView",
    "ExternalTypedDataInt32Array",
    "UnmodifiableTypedDataInt32ArrayView",
    "TypedDataUint32Array",
    "TypedDataUint32ArrayView",
    "ExternalTypedDataUint32Array",
    "UnmodifiableTypedDataUint32ArrayView",
    "TypedDataInt64Array",
    "TypedDataInt64ArrayView",
    "ExternalTypedDataInt64Array",
    "UnmodifiableTypedDataInt64ArrayView",
    "TypedDataUint64Array",
    "TypedDataUint64ArrayView",
    "ExternalTypedDataUint64Array",
    "UnmodifiableTypedDataUint64ArrayView",
    "TypedDataFloat32Array",
    "TypedDataFloat32ArrayView",
    "ExternalTypedDataFloat32Array",
    "UnmodifiableTypedDataFloat32ArrayView",
    "TypedDataFloat64Array",
    "TypedDataFloat64ArrayView",
    "ExternalTypedDataFloat64Array",
    "UnmodifiableTypedDataFloat64ArrayView",
    "TypedDataFloat32x4Array",
    "TypedDataFloat32x4ArrayView",
    "ExternalTypedDataFloat32x4Array",
    "UnmodifiableTypedDataFloat32x4ArrayView",
    "TypedDataInt32x4Array",
    "TypedDataInt32x4ArrayView",
    "ExternalTypedDataInt32x4Array",
    "UnmodifiableTypedDataInt32x4ArrayView",
    "TypedDataFloat64x2Array",
    "TypedDataFloat64x2ArrayView",
    "ExternalTypedDataFloat64x2Array",
    "UnmodifiableTypedDataFloat64x2ArrayView",
];

const TRAILING_CIDS: &[&str] = &[
    "ByteDataView",
    "UnmodifiableByteDataView",
    "ByteBuffer",
    "Null",
    "Dynamic",
    "Void",
    "Never",
];

pub const DART_3_3_CLASS_IDS: DartClassIdTable = DartClassIdTable {
    internal_only: INTERNAL_ONLY_CIDS_3_3,
    strings: STRING_CIDS_3_3,
};

pub const DART_3_4_CLASS_IDS: DartClassIdTable = DartClassIdTable {
    internal_only: INTERNAL_ONLY_CIDS_3_3,
    strings: STRING_CIDS,
};

pub const DART_3_6_CLASS_IDS: DartClassIdTable = DartClassIdTable {
    internal_only: INTERNAL_ONLY_CIDS_3_6,
    strings: STRING_CIDS,
};

pub const DART_3_9_CLASS_IDS: DartClassIdTable = DartClassIdTable {
    internal_only: INTERNAL_ONLY_CIDS_3_9,
    strings: STRING_CIDS,
};

const PREDEFINED_CLASS_IDS: DartClassIdTable = DART_3_9_CLASS_IDS;

impl DartClassIdTable {
    const fn groups(self) -> [&'static [&'static str]; 8] {
        [
            LEADING_CIDS,
            self.internal_only,
            INSTANCE_SINGLETON_CIDS,
            MAP_SET_ARRAY_CIDS,
            self.strings,
            FFI_CIDS,
            TYPED_DATA_CIDS,
            TRAILING_CIDS,
        ]
    }

    #[must_use]
    pub const fn predefined_count(self) -> u16 {
        let groups: [&'static [&'static str]; 8] = self.groups();
        let mut total: usize = 0;
        let mut index: usize = 0;
        while index < groups.len() {
            total += groups[index].len();
            index += 1;
        }
        total as u16
    }

    #[must_use]
    pub fn name(self, cid: u16) -> Option<&'static str> {
        let mut remaining: usize = usize::from(cid);
        for group in self.groups() {
            if let Some(name) = group.get(remaining) {
                return Some(name);
            }
            remaining -= group.len();
        }
        None
    }

    #[must_use]
    pub fn cid(self, name: &str) -> Option<u16> {
        self.names()
            .position(|candidate: &str| candidate == name)
            .and_then(|position: usize| u16::try_from(position).ok())
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        self.groups().into_iter().flatten().copied()
    }

    #[must_use]
    pub fn classes(self) -> Vec<PredefinedClass> {
        self.names()
            .zip(0_u16..)
            .map(|(name, cid): (&str, u16)| PredefinedClass {
                cid,
                name: name.to_owned(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredefinedClass {
    pub cid: u16,
    pub name: String,
}

#[must_use]
pub fn predefined_classes() -> Vec<PredefinedClass> {
    PREDEFINED_CLASS_IDS.classes()
}

#[must_use]
pub const fn predefined_count() -> u16 {
    PREDEFINED_CLASS_IDS.predefined_count()
}

#[must_use]
pub fn cid_table() -> DartCidTable {
    DartCidTable {
        version_hash: DART_3_12_VERSION_HASH.to_owned(),
        dart_sdk: DART_3_12_SDK.to_owned(),
        predefined_count: predefined_count(),
    }
}

#[must_use]
pub fn predefined_name(cid: u16) -> Option<&'static str> {
    PREDEFINED_CLASS_IDS.name(cid)
}

#[must_use]
pub fn is_application_cid(cid: u16) -> bool {
    cid >= predefined_count()
}

#[must_use]
pub fn matches_version(version_hash: &str) -> bool {
    version_hash == DART_3_12_VERSION_HASH
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn leading_cids_are_fixed() {
        assert_eq!(predefined_name(0), Some("Illegal"));
        assert_eq!(predefined_name(1), Some("NativePointer"));
        assert_eq!(predefined_name(2), Some("FreeListElement"));
        assert_eq!(predefined_name(3), Some("ForwardingCorpse"));
        assert_eq!(predefined_name(4), Some("Object"));
    }

    #[test]
    fn classes_and_lookup_agree() {
        let built: Vec<PredefinedClass> = predefined_classes();
        assert_eq!(built.len(), usize::from(predefined_count()));
        for entry in &built {
            assert_eq!(
                predefined_name(entry.cid),
                Some(entry.name.as_str()),
                "cid {} name mismatch",
                entry.cid
            );
            assert_eq!(PREDEFINED_CLASS_IDS.cid(&entry.name), Some(entry.cid));
        }
    }

    #[test]
    fn typed_data_quadruples_each_element() {
        let int8_cid: u16 = PREDEFINED_CLASS_IDS
            .cid("TypedDataInt8Array")
            .expect("int8 typed data present");
        assert_eq!(
            predefined_name(int8_cid + 1),
            Some("TypedDataInt8ArrayView")
        );
        assert_eq!(
            predefined_name(int8_cid + 2),
            Some("ExternalTypedDataInt8Array")
        );
        assert_eq!(
            predefined_name(int8_cid + 3),
            Some("UnmodifiableTypedDataInt8ArrayView")
        );
    }

    #[test]
    fn strings_and_arrays_precede_ffi() {
        let one_byte: u16 = PREDEFINED_CLASS_IDS
            .cid("OneByteString")
            .expect("OneByteString");
        let ffi_func: u16 = PREDEFINED_CLASS_IDS
            .cid("FfiNativeFunction")
            .expect("FfiNativeFunction");
        assert!(one_byte < ffi_func, "strings come before FFI in cid order");
    }

    #[test]
    fn trailing_pseudo_cids_are_last() {
        let count: u16 = predefined_count();
        assert_eq!(predefined_name(count - 1), Some("Never"));
        assert_eq!(predefined_name(count - 4), Some("Null"));
        assert_eq!(predefined_name(count), None);
    }

    #[test]
    fn application_cids_start_after_predefined() {
        let count: u16 = predefined_count();
        assert!(!is_application_cid(count - 1));
        assert!(is_application_cid(count));
        assert!(is_application_cid(count + 50));
    }

    #[test]
    fn version_hash_is_pinned() {
        assert!(matches_version(DART_3_12_VERSION_HASH));
        assert!(!matches_version("deadbeef"));
        assert_eq!(cid_table().dart_sdk, "3.12.2");
    }

    type ReleaseClassIds = (DartClassIdTable, u16, [(&'static str, u16); 6]);

    #[test]
    fn release_tables_move_the_class_ids_the_sdk_moved() {
        let expected: [ReleaseClassIds; 4] = [
            (
                DART_3_3_CLASS_IDS,
                176,
                [
                    ("Code", 18),
                    ("UnlinkedCall", 32),
                    ("Mint", 60),
                    ("String", 92),
                    ("FfiInt8", 98),
                    ("TypedDataInt8Array", 113),
                ],
            ),
            (
                DART_3_4_CLASS_IDS,
                174,
                [
                    ("Code", 18),
                    ("UnlinkedCall", 32),
                    ("Mint", 60),
                    ("String", 92),
                    ("FfiInt8", 96),
                    ("TypedDataInt8Array", 111),
                ],
            ),
            (
                DART_3_6_CLASS_IDS,
                175,
                [
                    ("Code", 18),
                    ("UnlinkedCall", 33),
                    ("Mint", 61),
                    ("String", 93),
                    ("FfiInt8", 97),
                    ("TypedDataInt8Array", 112),
                ],
            ),
            (
                DART_3_9_CLASS_IDS,
                175,
                [
                    ("Code", 18),
                    ("UnlinkedCall", 35),
                    ("Mint", 61),
                    ("String", 93),
                    ("FfiInt8", 97),
                    ("TypedDataInt8Array", 112),
                ],
            ),
        ];
        for (table, count, cids) in expected {
            assert_eq!(table.predefined_count(), count);
            assert_eq!(table.name(count - 1), Some("Never"));
            for (name, cid) in cids {
                assert_eq!(table.cid(name), Some(cid), "{name}");
                assert_eq!(table.name(cid), Some(name));
            }
        }
    }
}
