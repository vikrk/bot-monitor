"""Small local inventory and audit log for the independent manager."""
import os
import sqlite3
from contextlib import contextmanager

DB = os.environ.get("RVKOMI_MANAGER_DB", "/var/lib/rvkomi-server-manager/manager.sqlite3")


@contextmanager
def connect():
    os.makedirs(os.path.dirname(DB), mode=0o700, exist_ok=True)
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    try:
        db.executescript("""
      CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
        user TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('server','router')),
        key_path TEXT NOT NULL, fingerprint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        last_check TEXT, last_status TEXT
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT (datetime('now')),
        actor TEXT NOT NULL, node TEXT, action TEXT NOT NULL, result TEXT NOT NULL
      );
        """)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def audit(actor, node, action, result):
    with connect() as db:
        db.execute("INSERT INTO audit(actor,node,action,result) VALUES(?,?,?,?)",
                   (str(actor), node, action, result))

