mod btree;
mod format;
mod pager;
mod record;
mod recover;
mod schema;

use serde::Serialize;

use btree::{Entry, TreeKind, WalkOutcome, walk};
pub use format::{SqliteHeader, TextEncoding};
use pager::Pager;
pub use pager::WalReport;
pub use record::SqlValue;
use record::{apply_real_affinity, decode_record};
pub use recover::{FreelistReport, RecoveredRecord, RecoveryConfidence, RecoverySource};
use schema::{TableShape, table_shape};

const SCHEMA_ROOT: u32 = 1;
const SCHEMA_COLUMNS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
    #[error("not a SQLite 3 database: the 100-byte header with `SQLite format 3` is missing")]
    NotSqlite,
    #[error("header field `{field}` holds {value}, which no SQLite writer produces")]
    BadHeader { field: &'static str, value: u64 },
    #[error("page {page} is outside the {pages}-page database")]
    PageOutOfRange { page: u32, pages: u32 },
    #[error("cell at offset {offset}: {reason}")]
    BadCell { offset: usize, reason: String },
    #[error("write-ahead log: {0}")]
    Wal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub pages: usize,
    pub depth: usize,
    pub record_bytes: usize,
    pub overflow_pages: usize,
    pub rows_per_table: usize,
    pub recovered: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pages: 4_000_000,
            depth: 64,
            record_bytes: 64 * 1024 * 1024,
            overflow_pages: 1_000_000,
            rows_per_table: 1_000,
            recovered: 100_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InspectOptions {
    pub limits: Limits,
    pub only_table: Option<String>,
    pub recover_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rowid: Option<i64>,
    pub values: Vec<SqlValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableReport {
    pub name: String,
    pub root_page: u32,
    pub sql: String,
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rowid_alias: Option<usize>,
    pub without_rowid: bool,
    pub row_count: u64,
    pub rows: Vec<Row>,
    pub rows_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexReport {
    pub name: String,
    pub table: String,
    pub root_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    pub entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SchemaObject {
    pub name: String,
    pub table: String,
    pub sql: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SqliteReport {
    pub header: SqliteHeader,
    pub page_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal: Option<WalReport>,
    pub tables: Vec<TableReport>,
    pub indexes: Vec<IndexReport>,
    pub views: Vec<SchemaObject>,
    pub triggers: Vec<SchemaObject>,
    pub freelist: FreelistReport,
    pub recovered: Vec<RecoveredRecord>,
    pub problems: Vec<String>,
}

struct SchemaRow {
    kind: String,
    name: String,
    table: String,
    root: u32,
    sql: Option<String>,
}

pub fn inspect(
    db: &[u8],
    wal: Option<&[u8]>,
    options: &InspectOptions,
) -> Result<SqliteReport, SqliteError> {
    let header: SqliteHeader = SqliteHeader::parse(db)?;
    let (pager, wal_report): (Pager<'_>, Option<WalReport>) = Pager::new(db, &header, wal)?;
    let limits: &Limits = &options.limits;
    let mut budget: u64 = limits.pages as u64;
    let mut problems: Vec<String> = Vec::new();
    let mut schema_rows: Vec<SchemaRow> = Vec::new();
    let schema_walk: WalkOutcome = walk(
        &pager,
        SCHEMA_ROOT,
        TreeKind::Table,
        limits,
        &mut budget,
        &mut |entry: Entry| {
            if let Some(row) = schema_row(&entry.payload, header.text_encoding) {
                schema_rows.push(row);
            }
            true
        },
    );
    problems.extend(schema_walk.problems);
    let mut tables: Vec<TableReport> = Vec::new();
    let mut indexes: Vec<IndexReport> = Vec::new();
    let mut views: Vec<SchemaObject> = Vec::new();
    let mut triggers: Vec<SchemaObject> = Vec::new();
    let mut live_pages: Vec<u32> = schema_walk.pages;
    for row in &schema_rows {
        match row.kind.as_str() {
            "table" => {
                let sql: String = row.sql.clone().unwrap_or_default();
                let shape: TableShape = table_shape(&sql);
                let wanted: bool = options
                    .only_table
                    .as_ref()
                    .is_none_or(|name: &String| name.eq_ignore_ascii_case(&row.name));
                let mut report: TableReport = TableReport {
                    name: row.name.clone(),
                    root_page: row.root,
                    sql,
                    columns: shape.columns.clone(),
                    rowid_alias: shape.rowid_alias,
                    without_rowid: shape.without_rowid,
                    row_count: 0,
                    rows: Vec::new(),
                    rows_truncated: false,
                };
                if row.root == 0 {
                    tables.push(report);
                    continue;
                }
                let kind: TreeKind = if shape.without_rowid {
                    TreeKind::Index
                } else {
                    TreeKind::Table
                };
                let outcome: WalkOutcome = walk(
                    &pager,
                    row.root,
                    kind,
                    limits,
                    &mut budget,
                    &mut |entry: Entry| {
                        report.row_count += 1;
                        if !wanted || report.rows.len() >= limits.rows_per_table {
                            report.rows_truncated |= wanted;
                            return true;
                        }
                        match decode_record(&entry.payload, header.text_encoding, 32_767) {
                            Some(mut values) => {
                                if let (Some(alias), Some(rowid)) = (shape.rowid_alias, entry.rowid)
                                    && values.get(alias) == Some(&SqlValue::Null)
                                {
                                    values[alias] = SqlValue::Integer(rowid);
                                }
                                apply_real_affinity(&mut values, &shape.real_columns);
                                report.rows.push(Row {
                                    rowid: entry.rowid,
                                    values,
                                });
                            }
                            None => problems.push(format!(
                                "table {}: a record at rowid {:?} does not decode",
                                row.name, entry.rowid
                            )),
                        }
                        true
                    },
                );
                problems.extend(outcome.problems);
                if !shape.without_rowid {
                    live_pages.extend(outcome.pages);
                }
                tables.push(report);
            }
            "index" => {
                let mut entries: u64 = 0;
                if row.root != 0 {
                    let outcome: WalkOutcome = walk(
                        &pager,
                        row.root,
                        TreeKind::Index,
                        limits,
                        &mut budget,
                        &mut |_: Entry| {
                            entries += 1;
                            true
                        },
                    );
                    problems.extend(outcome.problems);
                }
                indexes.push(IndexReport {
                    name: row.name.clone(),
                    table: row.table.clone(),
                    root_page: row.root,
                    sql: row.sql.clone(),
                    entries,
                });
            }
            "view" | "trigger" => {
                let object: SchemaObject = SchemaObject {
                    name: row.name.clone(),
                    table: row.table.clone(),
                    sql: row.sql.clone().unwrap_or_default(),
                };
                if row.kind == "view" {
                    views.push(object);
                } else {
                    triggers.push(object);
                }
            }
            other => problems.push(format!("schema row {} has unknown type {other}", row.name)),
        }
    }
    let freelist: FreelistReport = recover::read_freelist(&pager, header.freelist_trunk, limits);
    let recovered: Vec<RecoveredRecord> = if options.recover_deleted {
        live_pages.sort_unstable();
        live_pages.dedup();
        recover::recover(
            &pager,
            &freelist,
            &live_pages,
            &recover::shapes(&tables),
            header.text_encoding,
            limits,
        )
    } else {
        Vec::new()
    };
    Ok(SqliteReport {
        page_count: pager.page_count,
        header,
        wal: wal_report,
        tables,
        indexes,
        views,
        triggers,
        freelist,
        recovered,
        problems,
    })
}

fn schema_row(payload: &[u8], encoding: TextEncoding) -> Option<SchemaRow> {
    let values: Vec<SqlValue> = decode_record(payload, encoding, SCHEMA_COLUMNS)?;
    let text = |index: usize| -> Option<String> {
        match values.get(index)? {
            SqlValue::Text(text) => Some(text.clone()),
            _ => None,
        }
    };
    let root: u32 = match values.get(3)? {
        SqlValue::Integer(value) => u32::try_from(*value).ok()?,
        SqlValue::Null => 0,
        _ => return None,
    };
    Some(SchemaRow {
        kind: text(0)?,
        name: text(1)?,
        table: text(2)?,
        root,
        sql: text(4),
    })
}
