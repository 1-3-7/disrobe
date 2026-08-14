use disrobe_bytes::{ByteReader, bounded_element_capacity};

use crate::error::{Error, Result};

const FOOTER_BYTES: usize = 16usize;
const HEADER_BYTES: usize = 8usize;
const MAGIC_LITTLE_ENDIAN: [u8; 2] = [b'J', b'L'];
const MAGIC_BIG_ENDIAN: [u8; 2] = [b'L', b'J'];
const HEADER_VALID_BYTE: u8 = 0x1au8;
const HEADER_OLD_FORMAT_BYTE: u8 = 0x80u8;
const MARK_FLAG_MASK: u32 = 0x8000_0000u32;
const MAX_ADAPTIVE_BYTES: usize = 5usize;
const MAX_DESCRIPTION_BYTES: usize = 1usize << 16;
const MAX_VIEW_DEPTH: usize = 8usize;
const MAX_COLUMNS: usize = 64usize;
const MAX_VIEW_ROWS: i64 = 1i64 << 20;
const MAX_MEMBERS: usize = 65_536usize;
const ROOT_DIRECTORY_NAME: &str = "<root>";

const SMALL_VECTOR_WIDTH: [[u8; 6]; 7] = [
    [8, 16, 1, 32, 2, 4],
    [4, 8, 1, 16, 2, 0],
    [2, 4, 8, 1, 0, 16],
    [2, 4, 0, 8, 1, 0],
    [1, 2, 4, 0, 8, 0],
    [1, 2, 4, 0, 0, 8],
    [1, 2, 0, 4, 0, 0],
];

fn malformed(reason: impl Into<String>) -> Error {
    Error::StarkitMetakit {
        reason: reason.into(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MetakitMember<'a> {
    pub(crate) path: String,
    pub(crate) declared_size: usize,
    pub(crate) stored: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    size: usize,
    position: usize,
}

impl Location {
    const EMPTY: Self = Self {
        size: 0usize,
        position: 0usize,
    };

    fn resolve(self, database: &[u8]) -> Result<&[u8]> {
        if self.size == 0usize {
            return Ok(&[]);
        }
        let end: usize = self
            .position
            .checked_add(self.size)
            .ok_or_else(|| malformed("column range overflows the address space"))?;
        database.get(self.position..end).ok_or_else(|| {
            malformed(format!(
                "column range {start}..{end} lies outside the {len}-byte database",
                start = self.position,
                len = database.len()
            ))
        })
    }
}

#[derive(Debug)]
struct Adaptive<'a> {
    reader: ByteReader<'a>,
}

impl<'a> Adaptive<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(bytes),
        }
    }

    fn exhausted(&self) -> bool {
        self.reader.is_empty()
    }

    fn value(&mut self) -> Result<i64> {
        let first: u8 = self
            .reader
            .peek_u8()
            .map_err(|_| malformed("adaptive integer starts past the end of the layout"))?;
        let negative: bool = first == 0u8;
        let mut accumulated: i64 = 0i64;
        for _ in 0usize..MAX_ADAPTIVE_BYTES {
            let byte: u8 = self
                .reader
                .read_u8()
                .map_err(|_| malformed("adaptive integer runs past the end of the layout"))?;
            accumulated = (accumulated << 7) + i64::from(byte);
            if byte & 0x80u8 != 0u8 {
                let plain: i64 = accumulated - 0x80i64;
                return Ok(if negative { !plain } else { plain });
            }
        }
        Err(malformed(format!(
            "adaptive integer longer than {MAX_ADAPTIVE_BYTES} bytes"
        )))
    }

    fn count(&mut self, what: &str) -> Result<usize> {
        let raw: i64 = self.value()?;
        if !(0i64..=MAX_VIEW_ROWS).contains(&raw) {
            return Err(malformed(format!(
                "{what} {raw} lies outside 0..={MAX_VIEW_ROWS}"
            )));
        }
        usize::try_from(raw).map_err(|_| malformed(format!("{what} {raw} does not fit a usize")))
    }

    fn location(&mut self) -> Result<Location> {
        let size: i64 = self.value()?;
        if size < 0i64 {
            return Err(malformed(format!("column size {size} is negative")));
        }
        if size == 0i64 {
            return Ok(Location::EMPTY);
        }
        let position: i64 = self.value()?;
        if position < 0i64 {
            return Err(malformed(format!("column position {position} is negative")));
        }
        Ok(Location {
            size: usize::try_from(size)
                .map_err(|_| malformed(format!("column size {size} does not fit a usize")))?,
            position: usize::try_from(position).map_err(|_| {
                malformed(format!("column position {position} does not fit a usize"))
            })?,
        })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        self.reader.read_bytes(count).map_err(|_| {
            malformed(format!(
                "{count} layout bytes run past the end of the block"
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ColumnKind {
    Integer,
    Real,
    Bytes,
    View(Vec<Column>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Column {
    name: String,
    kind: ColumnKind,
}

#[derive(Debug, Clone, Copy)]
enum ColumnLayout {
    Integer(Location),
    Unread,
    Bytes {
        data: Location,
        sizes: Location,
        memos: Location,
    },
    View(Location),
}

#[derive(Debug)]
struct ViewInstance {
    rows: usize,
    columns: Vec<ColumnLayout>,
}

#[derive(Debug)]
struct SubviewInstance {
    embedded_schema: Option<Vec<Column>>,
    view: ViewInstance,
}

impl SubviewInstance {
    fn schema<'s>(&'s self, inherited: &'s [Column]) -> &'s [Column] {
        self.embedded_schema.as_deref().unwrap_or(inherited)
    }
}

fn kind_for(code: u8) -> Result<ColumnKind> {
    match code {
        b'I' | b'L' => Ok(ColumnKind::Integer),
        b'F' | b'D' => Ok(ColumnKind::Real),
        b'S' | b'B' | b'M' => Ok(ColumnKind::Bytes),
        b'V' => Ok(ColumnKind::View(Vec::new())),
        other => Err(malformed(format!(
            "property type '{}' is not a Metakit type code",
            char::from(other)
        ))),
    }
}

fn parse_description(text: &str) -> Result<Vec<Column>> {
    let bytes: &[u8] = text.as_bytes();
    let mut at: usize = 0usize;
    let columns: Vec<Column> = parse_columns(bytes, &mut at, 0usize)?;
    if at != bytes.len() {
        return Err(malformed(format!(
            "view description has unparsed text from byte {at}"
        )));
    }
    Ok(columns)
}

fn parse_columns(text: &[u8], at: &mut usize, depth: usize) -> Result<Vec<Column>> {
    if depth > MAX_VIEW_DEPTH {
        return Err(malformed(format!(
            "view description nests deeper than {MAX_VIEW_DEPTH} levels"
        )));
    }
    let mut columns: Vec<Column> = Vec::new();
    while *at < text.len() && text[*at] != b']' {
        let start: usize = *at;
        while *at < text.len() && !matches!(text[*at], b':' | b'[' | b',' | b']') {
            *at += 1usize;
        }
        let name: &str = std::str::from_utf8(&text[start..*at])
            .map_err(|_| malformed("property name is not valid utf-8"))?;
        if name.is_empty() {
            return Err(malformed(format!(
                "view description has an unnamed property at byte {start}"
            )));
        }
        let kind: ColumnKind = match text.get(*at) {
            Some(b':') => {
                *at += 1usize;
                let code: u8 = *text
                    .get(*at)
                    .ok_or_else(|| malformed(format!("property '{name}' has no type code")))?;
                *at += 1usize;
                kind_for(code)?
            }
            Some(b'[') => {
                *at += 1usize;
                let nested: Vec<Column> = parse_columns(text, at, depth + 1usize)?;
                if text.get(*at) != Some(&b']') {
                    return Err(malformed(format!("subview '{name}' is not closed")));
                }
                *at += 1usize;
                ColumnKind::View(nested)
            }
            _ => {
                return Err(malformed(format!(
                    "property '{name}' declares neither a type nor a subview"
                )));
            }
        };
        if columns.len() >= MAX_COLUMNS {
            return Err(malformed(format!(
                "view declares more than {MAX_COLUMNS} properties"
            )));
        }
        columns.push(Column {
            name: name.to_owned(),
            kind,
        });
        if text.get(*at) == Some(&b',') {
            *at += 1usize;
        } else {
            break;
        }
    }
    Ok(columns)
}

fn read_instance(
    layout: &mut Adaptive<'_>,
    schema: &[Column],
    row_ceiling: usize,
) -> Result<ViewInstance> {
    let rows: usize = layout.count("view row count")?;
    if rows > row_ceiling {
        return Err(malformed(format!(
            "view declares {rows} rows in a {row_ceiling}-byte database"
        )));
    }
    let mut columns: Vec<ColumnLayout> = Vec::with_capacity(schema.len());
    if rows > 0usize {
        for column in schema {
            let entry: ColumnLayout = match &column.kind {
                ColumnKind::Integer => ColumnLayout::Integer(layout.location()?),
                ColumnKind::Real => {
                    let _fixed_width_column: Location = layout.location()?;
                    ColumnLayout::Unread
                }
                ColumnKind::Bytes => {
                    let data: Location = layout.location()?;
                    let sizes: Location = if data.size > 0usize {
                        layout.location()?
                    } else {
                        Location::EMPTY
                    };
                    let memos: Location = layout.location()?;
                    ColumnLayout::Bytes { data, sizes, memos }
                }
                ColumnKind::View(_) => ColumnLayout::View(layout.location()?),
            };
            columns.push(entry);
        }
    }
    Ok(ViewInstance { rows, columns })
}

fn read_subview(
    database: &[u8],
    location: Location,
    instances: usize,
    schema: &[Column],
) -> Result<Vec<SubviewInstance>> {
    if location.size == 0usize {
        return Ok((0usize..instances)
            .map(|_| SubviewInstance {
                embedded_schema: None,
                view: ViewInstance {
                    rows: 0usize,
                    columns: Vec::new(),
                },
            })
            .collect());
    }
    let block: &[u8] = location.resolve(database)?;
    let mut layout: Adaptive<'_> = Adaptive::new(block);
    let mut out: Vec<SubviewInstance> = Vec::with_capacity(bounded_element_capacity(
        instances as u64,
        2usize,
        block.len(),
    ));
    for _ in 0usize..instances {
        let description_len: usize = layout.count("subview description length")?;
        if description_len > MAX_DESCRIPTION_BYTES {
            return Err(malformed(format!(
                "subview description of {description_len} bytes exceeds {MAX_DESCRIPTION_BYTES}"
            )));
        }
        let embedded_schema: Option<Vec<Column>> = if description_len == 0usize {
            None
        } else {
            let text: &str = std::str::from_utf8(layout.take(description_len)?)
                .map_err(|_| malformed("subview description is not valid utf-8"))?;
            Some(parse_description(text)?)
        };
        let effective: &[Column] = embedded_schema.as_deref().unwrap_or(schema);
        let view: ViewInstance = read_instance(&mut layout, effective, database.len())?;
        out.push(SubviewInstance {
            embedded_schema,
            view,
        });
    }
    if !layout.exhausted() {
        return Err(malformed(format!(
            "{} bytes remain unread in a {}-byte subview layout",
            block.len() - layout.reader.position(),
            block.len()
        )));
    }
    Ok(out)
}

fn access_width(rows: usize, size: usize) -> Result<usize> {
    if rows == 0usize {
        return Ok(0usize);
    }
    let mut width: usize = size.saturating_mul(8usize) / rows;
    if rows <= 7usize && (1usize..=6usize).contains(&size) {
        width = usize::from(SMALL_VECTOR_WIDTH[rows - 1usize][size - 1usize]);
        if width == 0usize {
            return Err(malformed(format!(
                "an integer column of {rows} rows cannot occupy {size} bytes"
            )));
        }
    }
    if width > 64usize {
        return Err(malformed(format!(
            "integer column width {width} exceeds 64 bits"
        )));
    }
    if width & width.wrapping_sub(1usize) != 0usize {
        return Err(malformed(format!(
            "integer column width {width} is not a power of two"
        )));
    }
    Ok(width)
}

fn read_integer(data: &[u8], index: usize, width: usize) -> Result<i64> {
    let short = || malformed("integer column is shorter than its row count requires");
    match width {
        0usize => Ok(0i64),
        1usize | 2usize | 4usize => {
            let per_byte: usize = 8usize / width;
            let byte: u8 = *data.get(index / per_byte).ok_or_else(short)?;
            let shift: usize = (index % per_byte) * width;
            let mask: u8 = (1u8 << width) - 1u8;
            Ok(i64::from((byte >> shift) & mask))
        }
        8usize => Ok(i64::from(*data.get(index).ok_or_else(short)? as i8)),
        16usize => {
            let at: usize = index * 2usize;
            let raw: &[u8] = data.get(at..at + 2usize).ok_or_else(short)?;
            Ok(i64::from(i16::from_le_bytes([raw[0], raw[1]])))
        }
        32usize => {
            let at: usize = index * 4usize;
            let raw: &[u8] = data.get(at..at + 4usize).ok_or_else(short)?;
            Ok(i64::from(i32::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3],
            ])))
        }
        _ => {
            let at: usize = index * 8usize;
            let raw: &[u8] = data.get(at..at + 8usize).ok_or_else(short)?;
            Ok(i64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]))
        }
    }
}

fn read_integers(database: &[u8], location: Location, rows: usize) -> Result<Vec<i64>> {
    let width: usize = access_width(rows, location.size)?;
    let data: &[u8] = location.resolve(database)?;
    let needed: usize = rows.saturating_mul(width).div_ceil(8usize);
    if needed > data.len() {
        return Err(malformed(format!(
            "an integer column of {rows} rows at {width} bits needs {needed} bytes but holds {}",
            data.len()
        )));
    }
    let mut out: Vec<i64> = Vec::with_capacity(rows);
    for index in 0usize..rows {
        out.push(read_integer(data, index, width)?);
    }
    Ok(out)
}

fn read_memo_locations(
    database: &[u8],
    memos: Location,
    rows: usize,
) -> Result<Vec<Option<Location>>> {
    let mut out: Vec<Option<Location>> = vec![None; rows];
    if memos.size == 0usize {
        return Ok(out);
    }
    let block: &[u8] = memos.resolve(database)?;
    let mut layout: Adaptive<'_> = Adaptive::new(block);
    let mut row: i64 = 0i64;
    while !layout.exhausted() {
        row = row
            .checked_add(layout.value()?)
            .ok_or_else(|| malformed("memo row index overflows"))?;
        let index: usize = usize::try_from(row)
            .map_err(|_| malformed(format!("memo row index {row} is negative")))?;
        if index >= rows {
            return Err(malformed(format!(
                "memo names row {index} of a {rows}-row view"
            )));
        }
        if out[index].is_some() {
            return Err(malformed(format!("row {index} declares two memo payloads")));
        }
        out[index] = Some(layout.location()?);
        row = row
            .checked_add(1i64)
            .ok_or_else(|| malformed("memo row index overflows"))?;
    }
    Ok(out)
}

fn read_bytes_column<'a>(
    database: &'a [u8],
    layout: ColumnLayout,
    rows: usize,
    name: &str,
) -> Result<Vec<&'a [u8]>> {
    let ColumnLayout::Bytes { data, sizes, memos } = layout else {
        return Err(malformed(format!(
            "property '{name}' is not a bytes column"
        )));
    };
    let declared: Vec<i64> = read_integers(database, sizes, rows)?;
    let memo_locations: Vec<Option<Location>> = read_memo_locations(database, memos, rows)?;
    let inline: &[u8] = data.resolve(database)?;
    let mut out: Vec<&'a [u8]> = Vec::with_capacity(rows);
    let mut offset: usize = 0usize;
    for index in 0usize..rows {
        let size: usize = usize::try_from(declared[index]).map_err(|_| {
            malformed(format!(
                "property '{name}' row {index} declares {} bytes",
                declared[index]
            ))
        })?;
        if let Some(memo) = memo_locations[index] {
            if size != 0usize {
                return Err(malformed(format!(
                    "property '{name}' row {index} holds both {size} inline bytes and a memo"
                )));
            }
            out.push(memo.resolve(database)?);
            continue;
        }
        let end: usize = offset
            .checked_add(size)
            .ok_or_else(|| malformed(format!("property '{name}' item range overflows")))?;
        let item: &[u8] = inline.get(offset..end).ok_or_else(|| {
            malformed(format!(
                "property '{name}' row {index} reads {offset}..{end} of {} inline bytes",
                inline.len()
            ))
        })?;
        offset = end;
        out.push(item);
    }
    if offset != inline.len() {
        return Err(malformed(format!(
            "property '{name}' item sizes total {offset} but its data column holds {}",
            inline.len()
        )));
    }
    Ok(out)
}

fn integer_column(
    database: &[u8],
    layout: ColumnLayout,
    rows: usize,
    name: &str,
) -> Result<Vec<i64>> {
    let ColumnLayout::Integer(location) = layout else {
        return Err(malformed(format!(
            "property '{name}' is not an integer column"
        )));
    };
    read_integers(database, location, rows)
}

fn view_location(layout: ColumnLayout, name: &str) -> Result<Location> {
    match layout {
        ColumnLayout::View(location) => Ok(location),
        _ => Err(malformed(format!("property '{name}' is not a subview"))),
    }
}

fn column_index(schema: &[Column], name: &str) -> Result<usize> {
    schema
        .iter()
        .position(|column: &Column| column.name == name)
        .ok_or_else(|| malformed(format!("view declares no '{name}' property")))
}

fn subview_schema<'s>(schema: &'s [Column], index: usize, name: &str) -> Result<&'s [Column]> {
    match schema.get(index).map(|column: &Column| &column.kind) {
        Some(ColumnKind::View(nested)) => Ok(nested),
        _ => Err(malformed(format!(
            "property '{name}' is not declared as a subview"
        ))),
    }
}

fn decode_name(raw: &[u8], what: &str) -> Result<String> {
    let trimmed: &[u8] = raw.strip_suffix(&[0u8]).unwrap_or(raw);
    let text: &str = std::str::from_utf8(trimmed)
        .map_err(|_| malformed(format!("{what} is not valid utf-8")))?;
    if text.is_empty() {
        return Err(malformed(format!("{what} is empty")));
    }
    if text.contains('/') || text.contains('\\') || text.contains('\0') {
        return Err(malformed(format!(
            "{what} '{text}' carries a path separator"
        )));
    }
    Ok(text.to_owned())
}

fn directory_path(names: &[&[u8]], parents: &[i64], index: usize) -> Result<String> {
    if names.len() != parents.len() {
        return Err(malformed(
            "the directory name and parent columns disagree on their row count",
        ));
    }
    let mut components: Vec<String> = Vec::new();
    let mut cursor: usize = index;
    for _ in 0usize..=names.len() {
        let raw: &[u8] = names
            .get(cursor)
            .ok_or_else(|| malformed(format!("directory row {cursor} is out of range")))?;
        let name: String = decode_name(raw, "directory name")?;
        if name != ROOT_DIRECTORY_NAME {
            components.push(name);
        }
        let parent: i64 = parents[cursor];
        if parent < 0i64 {
            components.reverse();
            return Ok(components.join("/"));
        }
        let next: usize = usize::try_from(parent)
            .map_err(|_| malformed(format!("directory parent {parent} is out of range")))?;
        if next >= names.len() {
            return Err(malformed(format!(
                "directory row {cursor} names parent {next} of {} directories",
                names.len()
            )));
        }
        cursor = next;
    }
    Err(malformed(format!(
        "directory row {index} sits on a cyclic parent chain"
    )))
}

#[derive(Debug)]
struct Datafile<'a> {
    database: &'a [u8],
    structure: Location,
}

impl<'a> Datafile<'a> {
    fn locate(bytes: &'a [u8]) -> Result<Self> {
        let minimum: usize = FOOTER_BYTES + HEADER_BYTES;
        if bytes.len() < minimum {
            return Err(malformed(format!(
                "{} bytes is shorter than a Metakit header plus footer",
                bytes.len()
            )));
        }
        let mut footer: ByteReader<'a> = ByteReader::new(&bytes[bytes.len() - FOOTER_BYTES..]);
        let short = || malformed("the trailing Metakit commit mark is truncated");
        let _aside_mark: u32 = footer.read_u32_be().map_err(|_| short())?;
        let database_size: u32 = footer.read_u32_be().map_err(|_| short())?;
        let structure_mark: u32 = footer.read_u32_be().map_err(|_| short())?;
        let structure_position: u32 = footer.read_u32_be().map_err(|_| short())?;

        let database_size: usize = database_size as usize;
        let start: usize = bytes
            .len()
            .checked_sub(FOOTER_BYTES)
            .and_then(|end: usize| end.checked_sub(database_size))
            .ok_or_else(|| {
                malformed(format!(
                    "the commit mark claims a {database_size}-byte database inside {} bytes",
                    bytes.len()
                ))
            })?;
        let database: &'a [u8] = bytes
            .get(start..start + database_size)
            .ok_or_else(|| malformed("the claimed database range is out of bounds"))?;
        let header: &[u8] = database
            .get(0usize..HEADER_BYTES)
            .ok_or_else(|| malformed("the database is shorter than its header"))?;
        match [header[0], header[1]] {
            MAGIC_LITTLE_ENDIAN => {}
            MAGIC_BIG_ENDIAN => {
                return Err(Error::StarkitMetakitUnsupported {
                    feature: "byte-reversed 'LJ' datafile written on a big-endian host",
                });
            }
            other => {
                return Err(malformed(format!(
                    "the computed database start holds {other:?}, not a Metakit 'JL' header"
                )));
            }
        }
        if header[2] != HEADER_VALID_BYTE {
            return Err(malformed(format!(
                "the Metakit header reserved byte is {:#04x}, not {HEADER_VALID_BYTE:#04x}",
                header[2]
            )));
        }
        if header[3] == HEADER_OLD_FORMAT_BYTE {
            return Err(Error::StarkitMetakitUnsupported {
                feature: "pre-2.4 datafile layout flagged in the header",
            });
        }
        let declared_total: u32 = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let expected_total: usize = database_size + FOOTER_BYTES;
        if declared_total as usize != expected_total {
            return Err(malformed(format!(
                "the header spans {declared_total} bytes but the commit mark spans {expected_total}"
            )));
        }
        let structure: Location = Location {
            size: (structure_mark & !MARK_FLAG_MASK) as usize,
            position: structure_position as usize,
        };
        let structure_end: usize = structure
            .position
            .checked_add(structure.size)
            .ok_or_else(|| malformed("the structure block range overflows"))?;
        if structure.size == 0usize || structure_end > database_size {
            return Err(malformed(format!(
                "the structure block {start}..{structure_end} lies outside the {database_size}-byte database",
                start = structure.position
            )));
        }
        Ok(Self {
            database,
            structure,
        })
    }
}

pub(crate) fn read_starkit_members(bytes: &[u8]) -> Result<Vec<MetakitMember<'_>>> {
    let file: Datafile<'_> = Datafile::locate(bytes)?;
    let database: &[u8] = file.database;
    let block: &[u8] = file.structure.resolve(database)?;
    let mut layout: Adaptive<'_> = Adaptive::new(block);

    let format_code: i64 = layout.value()?;
    if format_code != 0i64 {
        return Err(Error::StarkitMetakitUnsupported {
            feature: "a structure block written with a non-zero format code",
        });
    }
    let description_len: usize = layout.count("structure description length")?;
    if description_len > MAX_DESCRIPTION_BYTES {
        return Err(malformed(format!(
            "structure description of {description_len} bytes exceeds {MAX_DESCRIPTION_BYTES}"
        )));
    }
    let description: &str = std::str::from_utf8(layout.take(description_len)?)
        .map_err(|_| malformed("structure description is not valid utf-8"))?;
    let schema: Vec<Column> = parse_description(description)?;
    let root: ViewInstance = read_instance(&mut layout, &schema, database.len())?;
    if !layout.exhausted() {
        return Err(malformed(format!(
            "{} bytes remain unread in the structure block",
            block.len() - layout.reader.position()
        )));
    }
    if root.rows != 1usize {
        return Err(malformed(format!(
            "the root view holds {} rows, not the single row a starkit declares",
            root.rows
        )));
    }

    let dirs_index: usize = column_index(&schema, "dirs")?;
    let dirs_schema: &[Column] = subview_schema(&schema, dirs_index, "dirs")?;
    let dirs_location: Location = view_location(root.columns[dirs_index], "dirs")?;
    let dirs_views: Vec<SubviewInstance> =
        read_subview(database, dirs_location, root.rows, dirs_schema)?;
    let dirs: &SubviewInstance = dirs_views
        .first()
        .ok_or_else(|| malformed("the root row carries no directory view"))?;
    let dirs_schema: &[Column] = dirs.schema(dirs_schema);
    if dirs.view.rows == 0usize {
        return Ok(Vec::new());
    }

    let name_index: usize = column_index(dirs_schema, "name")?;
    let parent_index: usize = column_index(dirs_schema, "parent")?;
    let files_index: usize = column_index(dirs_schema, "files")?;
    let directory_names: Vec<&[u8]> = read_bytes_column(
        database,
        dirs.view.columns[name_index],
        dirs.view.rows,
        "dirs.name",
    )?;
    let parents: Vec<i64> = integer_column(
        database,
        dirs.view.columns[parent_index],
        dirs.view.rows,
        "dirs.parent",
    )?;
    let files_schema: &[Column] = subview_schema(dirs_schema, files_index, "files")?;
    let files_location: Location = view_location(dirs.view.columns[files_index], "files")?;
    let file_views: Vec<SubviewInstance> =
        read_subview(database, files_location, dirs.view.rows, files_schema)?;

    let mut members: Vec<MetakitMember<'_>> = Vec::new();
    for (directory, files) in file_views.iter().enumerate() {
        if files.view.rows == 0usize {
            continue;
        }
        let schema: &[Column] = files.schema(files_schema);
        let name_index: usize = column_index(schema, "name")?;
        let size_index: usize = column_index(schema, "size")?;
        let contents_index: usize = column_index(schema, "contents")?;
        let names: Vec<&[u8]> = read_bytes_column(
            database,
            files.view.columns[name_index],
            files.view.rows,
            "files.name",
        )?;
        let sizes: Vec<i64> = integer_column(
            database,
            files.view.columns[size_index],
            files.view.rows,
            "files.size",
        )?;
        let contents: Vec<&[u8]> = read_bytes_column(
            database,
            files.view.columns[contents_index],
            files.view.rows,
            "files.contents",
        )?;
        let prefix: String = directory_path(&directory_names, &parents, directory)?;
        for row in 0usize..files.view.rows {
            if members.len() >= MAX_MEMBERS {
                return Err(malformed(format!(
                    "the directory declares more than {MAX_MEMBERS} members"
                )));
            }
            let name: String = decode_name(names[row], "member name")?;
            let declared_size: usize = usize::try_from(sizes[row]).map_err(|_| {
                malformed(format!("member '{name}' declares a size of {}", sizes[row]))
            })?;
            let path: String = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            members.push(MetakitMember {
                path,
                declared_size,
                stored: contents[row],
            });
        }
    }
    Ok(members)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_values_follow_the_seven_bit_terminator_rule() {
        let mut reader: Adaptive<'_> = Adaptive::new(&[0x80, 0x81, 0xbc, 0x03, 0x64, 0x90]);
        assert_eq!(reader.value().unwrap(), 0i64);
        assert_eq!(reader.value().unwrap(), 1i64);
        assert_eq!(reader.value().unwrap(), 60i64);
        assert_eq!(reader.value().unwrap(), 61_968i64);
        assert!(reader.exhausted());
    }

    #[test]
    fn a_leading_zero_octet_marks_a_complemented_value() {
        let mut reader: Adaptive<'_> = Adaptive::new(&[0x00, 0xff]);
        assert_eq!(reader.value().unwrap(), !0x7fi64);
    }

    #[test]
    fn an_unterminated_adaptive_value_is_refused() {
        let mut reader: Adaptive<'_> = Adaptive::new(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        assert!(reader.value().is_err());
    }

    #[test]
    fn small_integer_vectors_take_their_width_from_the_padding_table() {
        assert_eq!(access_width(1usize, 1usize).unwrap(), 8usize);
        assert_eq!(access_width(1usize, 6usize).unwrap(), 4usize);
        assert_eq!(access_width(2usize, 1usize).unwrap(), 4usize);
        assert_eq!(access_width(16usize, 8usize).unwrap(), 4usize);
        assert_eq!(access_width(16usize, 16usize).unwrap(), 8usize);
        assert_eq!(access_width(2usize, 8usize).unwrap(), 32usize);
        assert_eq!(access_width(29usize, 15usize).unwrap(), 4usize);
        assert_eq!(access_width(0usize, 40usize).unwrap(), 0usize);
    }

    #[test]
    fn an_integer_width_that_is_not_a_power_of_two_is_refused() {
        assert!(access_width(8usize, 24usize).is_err());
        assert!(access_width(4usize, 3usize).is_err());
    }

    #[test]
    fn sub_byte_integers_unpack_from_the_low_order_end() {
        let data: [u8; 8] = [0x47, 0x84, 0xba, 0x47, 0x85, 0x44, 0xf9, 0x64];
        let widths: Vec<i64> = (0usize..16usize)
            .map(|index: usize| read_integer(&data, index, 4usize).unwrap())
            .collect();
        assert_eq!(
            widths,
            vec![7, 4, 4, 8, 10, 11, 7, 4, 5, 8, 4, 4, 9, 15, 4, 6]
        );
    }

    #[test]
    fn eight_bit_integer_columns_are_signed() {
        assert_eq!(
            read_integer(&[0xff, 0x00, 0x02], 0usize, 8usize).unwrap(),
            -1i64
        );
        assert_eq!(
            read_integer(&[0xff, 0x00, 0x02], 2usize, 8usize).unwrap(),
            2i64
        );
    }

    #[test]
    fn the_starkit_description_parses_into_a_nested_schema() {
        let schema: Vec<Column> =
            parse_description("dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]")
                .unwrap();
        assert_eq!(schema.len(), 1usize);
        assert_eq!(schema[0].name, "dirs");
        let ColumnKind::View(dirs) = &schema[0].kind else {
            panic!("dirs must be a subview");
        };
        assert_eq!(dirs.len(), 3usize);
        assert_eq!(dirs[1].kind, ColumnKind::Integer);
        let ColumnKind::View(files) = &dirs[2].kind else {
            panic!("files must be a subview");
        };
        assert_eq!(
            files
                .iter()
                .map(|column: &Column| column.name.as_str())
                .collect::<Vec<&str>>(),
            vec!["name", "size", "date", "contents"]
        );
    }

    #[test]
    fn an_unclosed_subview_description_is_refused() {
        assert!(parse_description("dirs[name:S").is_err());
        assert!(parse_description("dirs[name:Q]").is_err());
        assert!(parse_description("dirs").is_err());
    }

    #[test]
    fn a_description_nested_past_the_depth_ceiling_is_refused() {
        let deep: String = format!(
            "{}a:S{}",
            "v[".repeat(MAX_VIEW_DEPTH + 2usize),
            "]".repeat(MAX_VIEW_DEPTH + 2usize)
        );
        assert!(parse_description(&deep).is_err());
    }

    #[test]
    fn a_short_buffer_is_not_a_datafile() {
        assert!(read_starkit_members(&[]).is_err());
        assert!(read_starkit_members(&[0u8; 23]).is_err());
    }

    #[test]
    fn a_commit_mark_claiming_more_bytes_than_the_file_holds_is_refused() {
        let mut bytes: Vec<u8> = vec![0u8; 64usize];
        bytes[48..52].copy_from_slice(&0u32.to_be_bytes());
        bytes[52..56].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        bytes[56..60].copy_from_slice(&0x8000_0004u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&0u32.to_be_bytes());
        assert!(read_starkit_members(&bytes).is_err());
    }
}
