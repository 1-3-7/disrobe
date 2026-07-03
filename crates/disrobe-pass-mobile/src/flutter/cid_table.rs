use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCidTable {
    pub version_hash: String,
    pub dart_sdk: String,
    pub predefined_count: u16,
}

pub const DART_3_12_VERSION_HASH: &str = "ace654289f5abc240509fc941453ebc5";

pub const DART_3_12_SDK: &str = "3.12.2";

const LEADING_CIDS: &[&str] = &[
    "Illegal",
    "NativePointer",
    "FreeListElement",
    "ForwardingCorpse",
];

const INTERNAL_ONLY_CIDS: &[&str] = &[
    "Object",
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

const MAP_SET_ARRAY_STRING_CIDS: &[&str] = &[
    "Map",
    "ConstMap",
    "Set",
    "ConstSet",
    "Array",
    "ImmutableArray",
    "GrowableObjectArray",
    "String",
    "OneByteString",
    "TwoByteString",
];

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

const TYPED_DATA_ELEMENTS: &[&str] = &[
    "Int8",
    "Uint8",
    "Uint8Clamped",
    "Int16",
    "Uint16",
    "Int32",
    "Uint32",
    "Int64",
    "Uint64",
    "Float32",
    "Float64",
    "Float32x4",
    "Int32x4",
    "Float64x2",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredefinedClass {
    pub cid: u16,
    pub name: String,
}

#[must_use]
pub fn predefined_classes() -> Vec<PredefinedClass> {
    let mut out: Vec<PredefinedClass> = Vec::with_capacity(512);
    let push = |name: String, out: &mut Vec<PredefinedClass>| {
        let cid: u16 = out.len() as u16;
        out.push(PredefinedClass { cid, name });
    };
    for name in LEADING_CIDS {
        push((*name).to_owned(), &mut out);
    }
    for name in INTERNAL_ONLY_CIDS {
        push((*name).to_owned(), &mut out);
    }
    for name in INSTANCE_SINGLETON_CIDS {
        push((*name).to_owned(), &mut out);
    }
    for name in MAP_SET_ARRAY_STRING_CIDS {
        push((*name).to_owned(), &mut out);
    }
    for name in FFI_CIDS {
        push((*name).to_owned(), &mut out);
    }
    for element in TYPED_DATA_ELEMENTS {
        push(format!("TypedData{element}Array"), &mut out);
        push(format!("TypedData{element}ArrayView"), &mut out);
        push(format!("ExternalTypedData{element}Array"), &mut out);
        push(format!("UnmodifiableTypedData{element}ArrayView"), &mut out);
    }
    for name in TRAILING_CIDS {
        push((*name).to_owned(), &mut out);
    }
    out
}

#[must_use]
pub fn predefined_count() -> u16 {
    (LEADING_CIDS.len()
        + INTERNAL_ONLY_CIDS.len()
        + INSTANCE_SINGLETON_CIDS.len()
        + MAP_SET_ARRAY_STRING_CIDS.len()
        + FFI_CIDS.len()
        + TYPED_DATA_ELEMENTS.len() * 4
        + TRAILING_CIDS.len()) as u16
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
    PREDEFINED_LOOKUP.get(usize::from(cid)).copied()
}

#[must_use]
pub fn is_application_cid(cid: u16) -> bool {
    cid >= predefined_count()
}

#[must_use]
pub fn matches_version(version_hash: &str) -> bool {
    version_hash == DART_3_12_VERSION_HASH
}

const PREDEFINED_LOOKUP: &[&str] = &[
    "Illegal",
    "NativePointer",
    "FreeListElement",
    "ForwardingCorpse",
    "Object",
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
    "Map",
    "ConstMap",
    "Set",
    "ConstSet",
    "Array",
    "ImmutableArray",
    "GrowableObjectArray",
    "String",
    "OneByteString",
    "TwoByteString",
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
    "ByteDataView",
    "UnmodifiableByteDataView",
    "ByteBuffer",
    "Null",
    "Dynamic",
    "Void",
    "Never",
];

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
    fn builder_and_lookup_agree() {
        let built: Vec<PredefinedClass> = predefined_classes();
        assert_eq!(built.len(), usize::from(predefined_count()));
        assert_eq!(built.len(), PREDEFINED_LOOKUP.len());
        for entry in &built {
            assert_eq!(
                predefined_name(entry.cid),
                Some(entry.name.as_str()),
                "cid {} name mismatch",
                entry.cid
            );
        }
    }

    #[test]
    fn typed_data_quadruples_each_element() {
        let int8_cid: u16 = predefined_classes()
            .iter()
            .find(|c: &&PredefinedClass| c.name == "TypedDataInt8Array")
            .expect("int8 typed data present")
            .cid;
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
        let one_byte: u16 = predefined_classes()
            .iter()
            .find(|c: &&PredefinedClass| c.name == "OneByteString")
            .expect("OneByteString")
            .cid;
        let ffi_func: u16 = predefined_classes()
            .iter()
            .find(|c: &&PredefinedClass| c.name == "FfiNativeFunction")
            .expect("FfiNativeFunction")
            .cid;
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
}
