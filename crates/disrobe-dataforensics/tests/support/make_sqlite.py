import json
import os
import shutil
import sqlite3
import sys

OUT = sys.argv[1]


def typed(value):
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "integer", "value": int(value)}
    if isinstance(value, int):
        return {"type": "integer", "value": value}
    if isinstance(value, float):
        return {"type": "real", "value": value}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": "blob", "value": bytes(value).hex()}
    raise TypeError(type(value))


def dump(conn):
    tables = {}
    for name, sql in conn.execute("SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        without_rowid = "WITHOUT ROWID" in sql.upper()
        if without_rowid:
            rows = [[None, [typed(v) for v in row]] for row in conn.execute(f'SELECT * FROM "{name}"')]
        else:
            rows = [[row[0], [typed(v) for v in row[1:]]] for row in conn.execute(f'SELECT rowid, * FROM "{name}" ORDER BY rowid')]
        tables[name] = {"rows": rows, "without_rowid": without_rowid}
    indexes = {}
    for name, table in conn.execute("SELECT name, tbl_name FROM sqlite_schema WHERE type = 'index' ORDER BY name"):
        indexes[name] = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
    views = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type = 'view'"))
    triggers = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type = 'trigger'"))
    return {"tables": tables, "indexes": indexes, "views": views, "triggers": triggers}


def fresh(name, page_size=4096, encoding=None, auto_vacuum=None):
    path = os.path.join(OUT, name)
    for suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute(f"PRAGMA page_size = {page_size}")
    if encoding:
        conn.execute(f"PRAGMA encoding = '{encoding}'")
    if auto_vacuum:
        conn.execute(f"PRAGMA auto_vacuum = {auto_vacuum}")
    conn.execute("PRAGMA secure_delete = OFF")
    return path, conn


INTEGERS = [0, 1, -1, 127, -128, 32767, -32768, 8388607, -8388608, 2**31 - 1, -2**31, 2**47 - 1, -2**47, 2**63 - 1, -2**63]
REALS = [0.5, -1.25, 3.141592653589793, 1e300, -2.5e-300]
TEXTS = ["", "plain", "unicode é中\U0001f600", "quote ' and \" chars", "x" * 3000]

reference = {}


def basic(name, page_size=4096, encoding=None, auto_vacuum=None):
    path, conn = fresh(name, page_size, encoding, auto_vacuum)
    conn.execute("BEGIN")
    conn.execute('CREATE TABLE kinds (id INTEGER PRIMARY KEY, i INTEGER, r REAL, t TEXT, b BLOB, n)')
    for index, value in enumerate(INTEGERS):
        conn.execute("INSERT INTO kinds (i, r, t, b, n) VALUES (?, ?, ?, ?, NULL)",
                     (value, REALS[index % len(REALS)], TEXTS[index % len(TEXTS)], bytes([index, 255 - index]) * (index + 1)))
    conn.execute('CREATE TABLE "big rows" (k TEXT, payload BLOB)')
    for size in (100, 5000, 70000, 300000):
        conn.execute('INSERT INTO "big rows" VALUES (?, ?)', (f"size-{size}", bytes((i * 7) % 256 for i in range(size))))
    conn.execute("CREATE TABLE many (a INTEGER, b TEXT)")
    for index in range(6000):
        conn.execute("INSERT INTO many VALUES (?, ?)", (index * 3, f"row {index:05d} " + "y" * (index % 50)))
    conn.execute("CREATE INDEX many_b ON many (b)")
    conn.execute("CREATE TABLE keyed (code TEXT PRIMARY KEY, amount REAL) WITHOUT ROWID")
    for index in range(400):
        conn.execute("INSERT INTO keyed VALUES (?, ?)", (f"k{index:04d}", index / 8))
    conn.execute("CREATE VIEW cheap AS SELECT * FROM keyed WHERE amount < 2")
    conn.execute("CREATE TRIGGER audit AFTER INSERT ON many BEGIN SELECT 1; END")
    conn.execute("COMMIT")
    reference[name] = dump(conn)
    conn.close()


def deleted(name):
    path, conn = fresh(name)
    conn.execute("BEGIN")
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, stars INTEGER)")
    ever = []
    for index in range(300):
        row = (index + 1000, f"title number {index}", "body text " * (index % 30 + 3), index % 5)
        conn.execute("INSERT INTO notes VALUES (?, ?, ?, ?)", row)
        ever.append(row)
    conn.execute("CREATE TABLE dropped (x INTEGER, y TEXT)")
    for index in range(500):
        conn.execute("INSERT INTO dropped VALUES (?, ?)", (index, f"dropped payload {index:04d} " * 3))
    conn.execute("COMMIT")
    gone = [row for row in ever if row[0] % 7 == 0 or 1100 <= row[0] < 1160]
    conn.execute("BEGIN")
    for row in gone:
        conn.execute("DELETE FROM notes WHERE id = ?", (row[0],))
    conn.execute("COMMIT")
    reference[name] = dump(conn)
    reference[name]["deleted"] = {"notes": [[row[0], [typed(v) for v in row]] for row in gone]}
    reference[name]["ever"] = {"notes": [[typed(v) for v in row] for row in ever]}
    conn.close()


def wal(name):
    path, conn = fresh(name)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA wal_autocheckpoint = 0")
    conn.execute("CREATE TABLE log (seq INTEGER PRIMARY KEY, message TEXT)")
    conn.execute("BEGIN")
    for index in range(50):
        conn.execute("INSERT INTO log (message) VALUES (?)", (f"checkpointed {index}",))
    conn.execute("COMMIT")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    base = dump(conn)
    for batch in range(3):
        conn.execute("BEGIN")
        for index in range(40):
            conn.execute("INSERT INTO log (message) VALUES (?)", (f"in wal {batch}-{index}",))
        conn.execute("UPDATE log SET message = 'rewritten' WHERE seq = 3")
        conn.execute("COMMIT")
    shutil.copyfile(path, path + ".copy")
    shutil.copyfile(path + "-wal", path + ".copy-wal")
    reference[name] = {"with_wal": dump(conn), "without_wal": base}
    conn.close()


basic("basic.db")
basic("page1k.db", page_size=1024)
basic("page64k.db", page_size=65536)
basic("utf16le.db", encoding="UTF-16le")
basic("utf16be.db", encoding="UTF-16be")
basic("autovacuum.db", auto_vacuum="FULL")
deleted("deleted.db")
wal("wal.db")
with open(os.path.join(OUT, "reference.json"), "w", encoding="utf-8") as handle:
    json.dump({"sqlite_version": sqlite3.sqlite_version, "databases": reference}, handle)
print(sqlite3.sqlite_version)
