use std::collections::BTreeMap;

pub type ObjId = (u32, u16);

static NULL: PdfObject = PdfObject::Null;

#[derive(Debug, Clone, PartialEq)]
pub enum PdfObject {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    String(Vec<u8>),
    Name(Vec<u8>),
    Array(Vec<PdfObject>),
    Dictionary(PdfDict),
    Stream(PdfStream),
    Reference(ObjId),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PdfDict {
    entries: Vec<(Vec<u8>, PdfObject)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PdfStream {
    pub dict: PdfDict,
    pub raw: Vec<u8>,
}

impl PdfDict {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, key: Vec<u8>, value: PdfObject) {
        self.entries.push((key, value));
    }

    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&PdfObject> {
        self.entries
            .iter()
            .find(|(k, _): &&(Vec<u8>, PdfObject)| k.as_slice() == key)
            .map(|(_, v): &(Vec<u8>, PdfObject)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &PdfObject)> {
        self.entries
            .iter()
            .map(|(k, v): &(Vec<u8>, PdfObject)| (k.as_slice(), v))
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut PdfObject> {
        self.entries
            .iter_mut()
            .map(|(_, v): &mut (Vec<u8>, PdfObject)| v)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn type_name(&self) -> Option<&[u8]> {
        match self.get(b"Type") {
            Some(PdfObject::Name(name)) => Some(name.as_slice()),
            _ => None,
        }
    }
}

impl PdfObject {
    #[must_use]
    pub fn as_dict(&self) -> Option<&PdfDict> {
        match self {
            Self::Dictionary(dict) => Some(dict),
            Self::Stream(stream) => Some(&stream.dict),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[PdfObject]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(name) => Some(name),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            Self::String(bytes) => Some(bytes),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_stream(&self) -> Option<&PdfStream> {
        match self {
            Self::Stream(stream) => Some(stream),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Real(value) => Some(*value as i64),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_reference(&self) -> Option<ObjId> {
        match self {
            Self::Reference(id) => Some(*id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionStatus {
    pub handler: String,
    pub decrypted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PdfDocument {
    pub objects: BTreeMap<u32, (u16, PdfObject)>,
    pub trailer: PdfDict,
    pub startxref_ok: bool,
    pub recovered_by_scan: bool,
    pub xref_stream_seen: bool,
    pub xref_table_seen: bool,
    pub encryption: Option<EncryptionStatus>,
}

impl PdfDocument {
    #[must_use]
    pub fn get(&self, number: u32) -> Option<&PdfObject> {
        self.objects
            .get(&number)
            .map(|(_, obj): &(u16, PdfObject)| obj)
    }

    pub fn resolve<'a>(&'a self, mut object: &'a PdfObject) -> &'a PdfObject {
        let mut budget: usize = super::limits::MAX_RESOLVE_STEPS;
        while let PdfObject::Reference((number, _)) = object {
            if budget == 0 {
                return &NULL;
            }
            budget -= 1;
            match self.get(*number) {
                Some(target) => object = target,
                None => return &NULL,
            }
        }
        object
    }

    #[must_use]
    pub fn resolve_dict<'a>(&'a self, object: &'a PdfObject) -> Option<&'a PdfDict> {
        self.resolve(object).as_dict()
    }

    #[must_use]
    pub fn dict_get<'a>(&'a self, dict: &'a PdfDict, key: &[u8]) -> Option<&'a PdfObject> {
        dict.get(key).map(|value: &PdfObject| self.resolve(value))
    }

    #[must_use]
    pub fn root(&self) -> Option<&PdfDict> {
        if let Some(root_ref) = self.trailer.get(b"Root")
            && let Some(dict) = self.resolve(root_ref).as_dict()
        {
            return Some(dict);
        }
        self.objects
            .values()
            .filter_map(|(_, obj): &(u16, PdfObject)| obj.as_dict())
            .find(|dict: &&PdfDict| dict.type_name() == Some(b"Catalog"))
    }
}
