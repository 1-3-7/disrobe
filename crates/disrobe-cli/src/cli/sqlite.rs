use std::path::{Path, PathBuf};

use disrobe_dataforensics::sqlite::{
    InspectOptions, Limits, RecoveryConfidence, SqliteReport, TableReport, inspect,
};

use crate::cli::output::{self, OutputFormat};

const MAX_DATABASE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 1024 * 1024 * 1024;

pub(crate) struct SqliteArgs {
    pub(crate) path: PathBuf,
    pub(crate) wal: Option<PathBuf>,
    pub(crate) table: Option<String>,
    pub(crate) rows: usize,
    pub(crate) recover: bool,
}

pub(crate) fn run(args: SqliteArgs, fmt: OutputFormat) -> miette::Result<()> {
    let db: Vec<u8> = read_bounded(&args.path, MAX_DATABASE_BYTES, "database")?;
    let wal_path: Option<PathBuf> = args.wal.or_else(|| {
        let mut sibling: std::ffi::OsString = args.path.as_os_str().to_owned();
        sibling.push("-wal");
        let sibling: PathBuf = PathBuf::from(sibling);
        sibling.is_file().then_some(sibling)
    });
    let wal: Option<Vec<u8>> = wal_path
        .as_deref()
        .map(|path: &Path| read_bounded(path, MAX_WAL_BYTES, "write-ahead log"))
        .transpose()?;
    let options: InspectOptions = InspectOptions {
        limits: Limits {
            rows_per_table: args.rows,
            ..Limits::default()
        },
        only_table: args.table,
        recover_deleted: args.recover,
    };
    let report: SqliteReport = inspect(&db, wal.as_deref(), &options)
        .map_err(|e| miette::miette!("DR-CLI-0440: {}: {e}", args.path.display()))?;
    output::emit(fmt, &report, || render(&report, wal_path.as_deref()))?;
    Ok(())
}

fn read_bounded(path: &Path, limit: u64, what: &str) -> miette::Result<Vec<u8>> {
    let size: u64 = std::fs::metadata(path)
        .map_err(|e| miette::miette!("DR-CLI-0441: cannot read {what} {}: {e}", path.display()))?
        .len();
    if size > limit {
        return Err(miette::miette!(
            "DR-CLI-0441: {what} {} is {size} bytes, above the {limit}-byte limit",
            path.display()
        ));
    }
    std::fs::read(path)
        .map_err(|e| miette::miette!("DR-CLI-0441: cannot read {what} {}: {e}", path.display()))
}

fn render(report: &SqliteReport, wal: Option<&Path>) {
    println!(
        "sqlite: {} pages of {} bytes, {:?} text, schema format {}, SQLite {}",
        report.page_count,
        report.header.page_size,
        report.header.text_encoding,
        report.header.schema_format,
        report.header.sqlite_version_number
    );
    if let (Some(path), Some(wal)) = (wal, &report.wal) {
        println!(
            "  wal:          {} ({} of {} frames valid, {} commits, {} pages applied)",
            path.display(),
            wal.valid_frames,
            wal.frames,
            wal.commits,
            wal.pages_overlaid
        );
    }
    for table in &report.tables {
        render_table(table);
    }
    for index in &report.indexes {
        println!(
            "  index {} on {}: {} entries",
            index.name, index.table, index.entries
        );
    }
    for view in &report.views {
        println!("  view {}", view.name);
    }
    for trigger in &report.triggers {
        println!("  trigger {} on {}", trigger.name, trigger.table);
    }
    println!(
        "  freelist:     {} trunk and {} leaf pages",
        report.freelist.trunk_pages.len(),
        report.freelist.leaf_pages.len()
    );
    if !report.recovered.is_empty() {
        let exact: usize = report
            .recovered
            .iter()
            .filter(|record| record.confidence == RecoveryConfidence::Exact)
            .count();
        println!(
            "  recovered:    {} deleted record(s), {exact} with an intact cell header (use --json for the values)",
            report.recovered.len()
        );
    }
    for problem in &report.problems {
        println!("  problem:      {problem}");
    }
}

fn render_table(table: &TableReport) {
    println!(
        "  table {} ({} rows{}): {}",
        table.name,
        table.row_count,
        if table.without_rowid {
            ", without rowid"
        } else {
            ""
        },
        table.columns.join(", ")
    );
    for row in &table.rows {
        let values: Vec<String> = row
            .values
            .iter()
            .map(|value| serde_json::to_string(value).unwrap_or_default())
            .collect();
        match row.rowid {
            Some(rowid) => println!("    {rowid}: {}", values.join(" | ")),
            None => println!("    {}", values.join(" | ")),
        }
    }
    if table.rows_truncated {
        println!("    ... more rows; raise --rows to see them");
    }
}
