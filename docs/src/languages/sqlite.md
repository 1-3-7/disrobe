# SQLite databases

`disrobe sqlite <database>` reads a SQLite 3 database file without opening it through SQLite, so a damaged, locked or deliberately malformed file still yields what can be read, and deleted records come back alongside the live ones.

```sh
disrobe sqlite app.db                     # schema, row counts and the first rows of each table
disrobe sqlite app.db --table messages --rows 10000
disrobe sqlite app.db --recover --json    # also carve deleted records
disrobe sqlite app.db --wal app.db-wal    # apply a write-ahead log explicitly
```

## What it reports

- The 100-byte header: page size, reserved bytes, text encoding (UTF-8, UTF-16LE, UTF-16BE), schema format, change counter, freelist size, user version, application id and the SQLite version that last wrote the file.
- Every schema object from `sqlite_schema`: tables with their declared columns (quoted names included), the `INTEGER PRIMARY KEY` column that aliases the rowid, `WITHOUT ROWID` tables, indexes with their entry counts, views and triggers with their SQL.
- Rows of every table, decoded from each record's serial types: NULL, integers of 1 to 8 bytes, IEEE doubles, text in the database's encoding, and blobs as hex. Payloads that spill onto overflow pages are reassembled.
- The write-ahead log. A `<database>-wal` file beside the database is applied automatically (or name one with `--wal`). Frames are checked against the WAL header's salts and the cumulative checksum, and only frames up to the last commit are applied, as SQLite itself does. The report counts frames, valid frames, commits and the pages they replace.
- The freelist: trunk and leaf pages.

## Deleted records

`--recover` carves deleted records from three places SQLite does not overwrite unless `secure_delete` is on:

| Source | What remains | Confidence |
|---|---|---|
| Freelist pages | Whole former b-tree pages, often with every cell intact | `exact` when a cell parses as a full table-leaf cell |
| Freeblocks inside live pages | A deleted cell whose first four bytes now hold the freeblock link | `partial`: the record decodes but the rowid is lost |
| Unallocated space between the cell pointers and the cell content | Cells that page defragmentation moved but did not erase | `exact` or `partial` |

A carved record is kept only when its column count and every value's storage class fit a table's declared column affinities (INTEGER columns hold integers, TEXT columns text, REAL columns numbers); it is attributed to that table when exactly one fits, and otherwise the report lists the candidate tables. Records whose text is empty or holds control characters, or whose every value is NULL, are not reported, because random bytes produce such records. A freeblock's first cell has its payload length, rowid and record-header length overwritten; when the table's schema fixes the column count, the serial types that follow are read directly, and an `INTEGER PRIMARY KEY` first column is assumed to be the NULL its rowid alias stores.

## Evidence

The grader in `crates/disrobe-dataforensics/tests/sqlite_reference.rs` builds databases with CPython's `sqlite3` module (the reference reader): every serial type and integer width, text in UTF-8, UTF-16LE and UTF-16BE, rows that spill across overflow pages, 6,000-row tables with interior pages and an index, a `WITHOUT ROWID` table, a view and a trigger, page sizes of 1,024, 4,096 and 65,536 bytes, an `auto_vacuum = FULL` database with pointer-map pages, a WAL holding three uncheckpointed commits, and a database with deleted rows and a dropped table. Every live row must equal what `sqlite3` returns, with and without the WAL. For the deleted rows, no recovered record may differ from a row the generator ever wrote, and at least 19 in 20 of the deleted rows whose bytes are still in the file (located by searching the file independently) must come back. On the committed generator with SQLite 3.50.4, 95 rows are deleted, 74 of them remain in the file, and all 74 are recovered, 48 of them with their rowid; the other 21 were overwritten by later writes. A record whose stored text is altered must fail the comparison (the mutation control), and 400 randomly corrupted and truncated databases must produce a report or a typed error, never a panic.

## Limits

- Pages visited, b-tree depth (64), record size (64 MiB), overflow chain length and the number of rows and recovered records are bounded; the report's `problems` list names every subtree that a bound or a damaged page stopped.
- Deleted rows of a dropped table are not attributed, because its schema row is gone.
- A freeblock cell whose overwritten bytes reach past its first serial type is not recovered unless that column is the `INTEGER PRIMARY KEY`.
- A value stored in a column of a different declared type (SQLite allows a blob in a TEXT column) is not recovered by carving, because accepting it admits false positives.
- `WITHOUT ROWID` rows are listed in key order.
