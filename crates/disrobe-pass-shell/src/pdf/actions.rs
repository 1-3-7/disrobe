use std::collections::BTreeSet;

use super::filters::{Decoded, decode_stream};
use super::limits;
use super::names::{self, extract_javascript, name_to_string, pdf_string_to_text};
use super::object::{ObjId, PdfDict, PdfDocument, PdfObject};
use super::report::{ActionFinding, EmbeddedFileFinding, JsFinding, sha256_hex};

#[derive(Debug, Default)]
pub struct Findings {
    pub javascript: Vec<JsFinding>,
    pub actions: Vec<ActionFinding>,
    pub embedded_files: Vec<EmbeddedFileFinding>,
    pub open_action: bool,
}

#[must_use]
pub fn collect(doc: &PdfDocument) -> Findings {
    let mut collector: Collector<'_> = Collector::new(doc);
    collector.walk_catalog();
    collector.walk_pages();
    collector.walk_acroform();
    collector.global_sweep();
    Findings {
        javascript: collector.javascript,
        actions: collector.actions,
        embedded_files: collector.embedded_files,
        open_action: collector.open_action,
    }
}

struct Collector<'a> {
    doc: &'a PdfDocument,
    javascript: Vec<JsFinding>,
    actions: Vec<ActionFinding>,
    embedded_files: Vec<EmbeddedFileFinding>,
    open_action: bool,
    visited: BTreeSet<ObjId>,
    visited_pages: BTreeSet<ObjId>,
    seen_scripts: BTreeSet<String>,
    seen_files: BTreeSet<String>,
    budget: usize,
}

impl<'a> Collector<'a> {
    fn new(doc: &'a PdfDocument) -> Self {
        Self {
            doc,
            javascript: Vec::new(),
            actions: Vec::new(),
            embedded_files: Vec::new(),
            open_action: false,
            visited: BTreeSet::new(),
            visited_pages: BTreeSet::new(),
            seen_scripts: BTreeSet::new(),
            seen_files: BTreeSet::new(),
            budget: limits::MAX_WALK_NODES,
        }
    }

    fn walk_catalog(&mut self) {
        let doc: &PdfDocument = self.doc;
        let Some(root): Option<&PdfDict> = doc.root() else {
            return;
        };
        if let Some(open_action) = root.get(b"OpenAction") {
            self.open_action = true;
            let open_action: PdfObject = open_action.clone();
            self.handle_action(&open_action, "OpenAction", 0);
        }
        self.walk_additional_actions(root, "Catalog");
        if let Some(PdfObject::Dictionary(names_dict)) = doc.dict_get(root, b"Names") {
            let names_dict: PdfDict = names_dict.clone();
            if let Some(js_tree) = names_dict.get(b"JavaScript") {
                for (name, value) in names::collect_name_tree(doc, js_tree) {
                    let origin: String = format!("Names/JavaScript:{name}");
                    match value.as_dict().and_then(|dict: &PdfDict| dict.get(b"JS")) {
                        Some(js) => self.add_js(&origin, Some(name.clone()), js, &value),
                        None => self.handle_action(&value, &origin, 0),
                    }
                }
            }
            if let Some(ef_tree) = names_dict.get(b"EmbeddedFiles") {
                for (name, value) in names::collect_name_tree(doc, ef_tree) {
                    let origin: String = format!("Names/EmbeddedFiles:{name}");
                    self.add_embedded(&value, &origin, Some(name));
                }
            }
        }
    }

    fn walk_pages(&mut self) {
        let doc: &PdfDocument = self.doc;
        let Some(root): Option<&PdfDict> = doc.root() else {
            return;
        };
        let Some(pages): Option<&PdfObject> = doc.dict_get(root, b"Pages") else {
            return;
        };
        let mut work: Vec<PdfObject> = vec![pages.clone()];
        while let Some(node_obj) = work.pop() {
            if self.budget == 0 {
                break;
            }
            if let Some(id) = node_obj.as_reference()
                && !self.visited_pages.insert(id)
            {
                continue;
            }
            let Some(node): Option<&PdfDict> = doc.resolve(&node_obj).as_dict() else {
                continue;
            };
            let node: PdfDict = node.clone();
            if node.type_name() == Some(b"Pages") {
                if let Some(PdfObject::Array(kids)) = doc.dict_get(&node, b"Kids") {
                    for kid in kids {
                        if work.len() < limits::MAX_WALK_NODES {
                            work.push(kid.clone());
                        }
                    }
                }
            } else {
                self.walk_additional_actions(&node, "Page");
                self.walk_annotations(&node);
            }
        }
    }

    fn walk_annotations(&mut self, page: &PdfDict) {
        let doc: &PdfDocument = self.doc;
        let Some(PdfObject::Array(annotations)): Option<&PdfObject> = doc.dict_get(page, b"Annots")
        else {
            return;
        };
        let annotations: Vec<PdfObject> = annotations.clone();
        for annotation_obj in annotations {
            let Some(annotation): Option<&PdfDict> = doc.resolve(&annotation_obj).as_dict() else {
                continue;
            };
            let annotation: PdfDict = annotation.clone();
            if let Some(action) = annotation.get(b"A") {
                let action: PdfObject = action.clone();
                self.handle_action(&action, "Annot/A", 0);
            }
            self.walk_additional_actions(&annotation, "Annot");
            if annotation.get(b"Subtype").and_then(PdfObject::as_name) == Some(b"FileAttachment")
                && let Some(filespec) = annotation.get(b"FS")
            {
                let filespec: PdfObject = filespec.clone();
                self.add_embedded(&filespec, "Annot/FileAttachment", None);
            }
        }
    }

    fn walk_acroform(&mut self) {
        let doc: &PdfDocument = self.doc;
        let Some(root): Option<&PdfDict> = doc.root() else {
            return;
        };
        let Some(PdfObject::Dictionary(form)): Option<&PdfObject> = doc.dict_get(root, b"AcroForm")
        else {
            return;
        };
        let Some(PdfObject::Array(fields)): Option<&PdfObject> = doc.dict_get(form, b"Fields")
        else {
            return;
        };
        let mut work: Vec<PdfObject> = fields.clone();
        let mut visited_fields: BTreeSet<ObjId> = BTreeSet::new();
        let mut count: usize = 0;
        while let Some(field_obj) = work.pop() {
            count += 1;
            if count > limits::MAX_WALK_NODES || self.budget == 0 {
                break;
            }
            if let Some(id) = field_obj.as_reference()
                && !visited_fields.insert(id)
            {
                continue;
            }
            let Some(field): Option<&PdfDict> = doc.resolve(&field_obj).as_dict() else {
                continue;
            };
            let field: PdfDict = field.clone();
            if let Some(action) = field.get(b"A") {
                let action: PdfObject = action.clone();
                self.handle_action(&action, "Field/A", 0);
            }
            self.walk_additional_actions(&field, "Field");
            if let Some(PdfObject::Array(kids)) = doc.dict_get(&field, b"Kids") {
                for kid in kids {
                    if work.len() < limits::MAX_WALK_NODES {
                        work.push(kid.clone());
                    }
                }
            }
        }
    }

    fn walk_additional_actions(&mut self, dict: &PdfDict, scope: &str) {
        let doc: &PdfDocument = self.doc;
        let Some(PdfObject::Dictionary(additional)): Option<&PdfObject> = doc.dict_get(dict, b"AA")
        else {
            return;
        };
        let events: Vec<(Vec<u8>, PdfObject)> = additional
            .iter()
            .map(|(key, value): (&[u8], &PdfObject)| (key.to_vec(), value.clone()))
            .collect();
        for (event, action) in events {
            let origin: String = format!("{scope}/AA/{}", String::from_utf8_lossy(&event));
            self.handle_action(&action, &origin, 0);
        }
    }

    fn handle_action(&mut self, object: &PdfObject, origin: &str, depth: usize) {
        let doc: &PdfDocument = self.doc;
        if depth > limits::MAX_ACTION_DEPTH || self.budget == 0 {
            return;
        }
        self.budget -= 1;
        if let Some(id) = object.as_reference()
            && !self.visited.insert(id)
        {
            return;
        }
        let Some(dict): Option<&PdfDict> = doc.resolve(object).as_dict() else {
            return;
        };
        let dict: PdfDict = dict.clone();
        match dict.get(b"S").and_then(PdfObject::as_name) {
            Some(b"JavaScript") => {
                if let Some(js) = dict.get(b"JS") {
                    self.add_js(origin, None, js, js);
                }
            }
            Some(b"Launch") => {
                let target: String = self.launch_target(&dict);
                self.push_action("Launch", origin, target);
            }
            Some(b"URI") => {
                let target: String = doc
                    .dict_get(&dict, b"URI")
                    .and_then(PdfObject::as_string)
                    .map_or_else(String::new, pdf_string_to_text);
                self.push_action("URI", origin, target);
            }
            Some(b"GoToR") => {
                let target: String = dict
                    .get(b"F")
                    .map_or_else(String::new, |value: &PdfObject| self.filespec_target(value));
                self.push_action("GoToR", origin, target);
            }
            Some(b"SubmitForm") => {
                let target: String = dict
                    .get(b"F")
                    .map_or_else(String::new, |value: &PdfObject| self.filespec_target(value));
                self.push_action("SubmitForm", origin, target);
            }
            Some(b"ImportData") => {
                let target: String = dict
                    .get(b"F")
                    .map_or_else(String::new, |value: &PdfObject| self.filespec_target(value));
                self.push_action("ImportData", origin, target);
            }
            Some(other) if !other.is_empty() => {
                self.push_action(&name_to_string(other), origin, String::new());
            }
            _ => {}
        }
        if let Some(next) = dict.get(b"Next") {
            let next_origin: String = format!("{origin}/Next");
            match doc.resolve(next) {
                PdfObject::Array(items) => {
                    let items: Vec<PdfObject> = items.clone();
                    for item in items {
                        self.handle_action(&item, &next_origin, depth + 1);
                    }
                }
                other => {
                    let other: PdfObject = other.clone();
                    self.handle_action(&other, &next_origin, depth + 1);
                }
            }
        }
    }

    fn launch_target(&self, dict: &PdfDict) -> String {
        let doc: &PdfDocument = self.doc;
        if let Some(file) = dict.get(b"F") {
            let target: String = self.filespec_target(file);
            if !target.is_empty() {
                return target;
            }
        }
        if let Some(PdfObject::Dictionary(win)) = doc.dict_get(dict, b"Win")
            && let Some(file) = win.get(b"F")
        {
            return self.filespec_target(file);
        }
        String::new()
    }

    fn filespec_target(&self, object: &PdfObject) -> String {
        let doc: &PdfDocument = self.doc;
        match doc.resolve(object) {
            PdfObject::String(bytes) => pdf_string_to_text(bytes),
            PdfObject::Dictionary(dict) => {
                for key in [b"UF".as_slice(), b"F", b"DOS", b"Unix", b"Mac"] {
                    if let Some(bytes) = doc.dict_get(dict, key).and_then(PdfObject::as_string) {
                        return pdf_string_to_text(bytes);
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn add_js(
        &mut self,
        origin: &str,
        name: Option<String>,
        value: &PdfObject,
        source: &PdfObject,
    ) {
        let doc: &PdfDocument = self.doc;
        let Some(script): Option<String> = extract_javascript(doc, value) else {
            return;
        };
        let mut deobfuscation: Vec<String> = Vec::new();
        match doc.resolve(source) {
            PdfObject::Array(_) => deobfuscation.push("concatenated-strings".to_owned()),
            PdfObject::Stream(_) => deobfuscation.push("filter-decoded".to_owned()),
            _ => {}
        }
        let sha256: String = sha256_hex(script.as_bytes());
        if !self.seen_scripts.insert(sha256.clone())
            || self.javascript.len() >= limits::MAX_FINDINGS
        {
            return;
        }
        self.javascript.push(JsFinding {
            origin: origin.to_owned(),
            name,
            bytes: script.len(),
            sha256,
            script,
            deobfuscation,
        });
    }

    fn push_action(&mut self, kind: &str, origin: &str, target: String) {
        if self.actions.len() >= limits::MAX_FINDINGS {
            return;
        }
        self.actions.push(ActionFinding {
            kind: kind.to_owned(),
            origin: origin.to_owned(),
            target,
        });
    }

    fn add_embedded(&mut self, object: &PdfObject, origin: &str, name_hint: Option<String>) {
        let doc: &PdfDocument = self.doc;
        let Some(filespec): Option<&PdfDict> = doc.resolve(object).as_dict() else {
            return;
        };
        let filespec: PdfDict = filespec.clone();
        let name: String = name_hint
            .or_else(|| {
                for key in [b"UF".as_slice(), b"F"] {
                    if let Some(bytes) = doc.dict_get(&filespec, key).and_then(PdfObject::as_string)
                    {
                        return Some(pdf_string_to_text(bytes));
                    }
                }
                None
            })
            .unwrap_or_else(|| "<embedded>".to_owned());
        let Some(PdfObject::Dictionary(embedded)): Option<&PdfObject> =
            doc.dict_get(&filespec, b"EF")
        else {
            return;
        };
        let embedded: PdfDict = embedded.clone();
        let stream_ref: Option<&PdfObject> = [b"F".as_slice(), b"UF", b"DOS", b"Unix", b"Mac"]
            .into_iter()
            .find_map(|key: &[u8]| embedded.get(key));
        let Some(stream_ref): Option<&PdfObject> = stream_ref else {
            return;
        };
        let Some(stream): Option<&super::object::PdfStream> = doc.resolve(stream_ref).as_stream()
        else {
            return;
        };
        let stream: super::object::PdfStream = stream.clone();
        let decoded: Decoded = decode_stream(doc, &stream);
        let subtype: Option<String> = stream
            .dict
            .get(b"Subtype")
            .and_then(PdfObject::as_name)
            .map(name_to_string);
        let sha256: String = sha256_hex(&decoded.data);
        if !self.seen_files.insert(sha256.clone())
            || self.embedded_files.len() >= limits::MAX_FINDINGS
        {
            return;
        }
        let preview: Option<String> = printable_preview(&decoded.data);
        self.embedded_files.push(EmbeddedFileFinding {
            name,
            origin: origin.to_owned(),
            subtype,
            bytes: decoded.data.len(),
            sha256,
            preview,
        });
    }

    fn global_sweep(&mut self) {
        let doc: &PdfDocument = self.doc;
        let numbers: Vec<u32> = doc.objects.keys().copied().collect();
        for number in numbers {
            if self.budget == 0 {
                break;
            }
            let Some(object): Option<&PdfObject> = doc.get(number) else {
                continue;
            };
            let Some(dict): Option<&PdfDict> = object.as_dict() else {
                continue;
            };
            let is_javascript: bool = dict.get(b"S").and_then(PdfObject::as_name)
                == Some(b"JavaScript")
                || dict.get(b"JS").is_some();
            if is_javascript && let Some(js) = dict.get(b"JS") {
                self.add_js(&format!("object {number}"), None, js, js);
            }
            if dict.type_name() == Some(b"Filespec") || dict.get(b"EF").is_some() {
                let object: PdfObject = object.clone();
                self.add_embedded(&object, &format!("object {number}"), None);
            }
        }
    }
}

fn printable_preview(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let sample: &[u8] = &data[..data.len().min(512)];
    let printable: usize = sample
        .iter()
        .filter(|byte: &&u8| matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
        .count();
    if printable * 10 < sample.len() * 8 {
        return None;
    }
    Some(
        sample
            .iter()
            .map(|byte: &u8| {
                if matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect(),
    )
}
