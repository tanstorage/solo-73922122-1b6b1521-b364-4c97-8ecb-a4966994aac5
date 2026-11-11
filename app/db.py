"""SQLite persistence shared by all web workers.

The business database is only written in short transactions.  In particular,
an import is validated and staged in a separate temporary database before a
short final transaction copies the visible rows.  That keeps revocation
responsive while a large file is being read and gives the final transaction a
single place to enforce the revocation barrier.
"""

from __future__ import annotations

from contextlib import closing
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from typing import Iterable, Iterator

from app.config import ProbeConfig

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = int(os.environ.get("SQLITE_BUSY_TIMEOUT_MS", "30000"))
SCHEMA = """
CREATE TABLE IF NOT EXISTS probes (
    probe_id TEXT PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    authorized_hosts_json TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    configured_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    probe_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    host TEXT NOT NULL,
    time INTEGER NOT NULL,
    rule TEXT NOT NULL,
    fields_json TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    UNIQUE (probe_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_imported
    ON alerts(imported_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_probe_time
    ON alerts(probe_id, time DESC, id DESC);

CREATE TABLE IF NOT EXISTS import_batches (
    batch_id TEXT PRIMARY KEY,
    probe_id TEXT NOT NULL,
    file_name TEXT,
    size_bytes INTEGER NOT NULL,
    total_lines INTEGER NOT NULL,
    imported_lines INTEGER NOT NULL,
    skipped_lines INTEGER NOT NULL,
    status TEXT NOT NULL,
    failure_code TEXT,
    failure_message TEXT,
    failure_line INTEGER,
    started_at INTEGER NOT NULL,
    finished_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_import_batches_finished
    ON import_batches(finished_at DESC);
"""


def _connect(path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    db_path = str(path)
    if read_only:
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro",
            uri=True,
            timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
    else:
        conn = sqlite3.connect(
            db_path,
            timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    # Temp sorting/join structures may be needed by the final copy; keep them
    # on disk so a huge batch never turns into a huge in-memory SQLite cache.
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def open_read_connection(path: str | Path) -> sqlite3.Connection:
    return _connect(path, read_only=True)


def open_write_connection(path: str | Path) -> sqlite3.Connection:
    return _connect(path)


def initialize_storage(db_path: str | Path, probes: dict[str, ProbeConfig]) -> None:
    """Create the schema and make the configured probes known in SQLite.

    Revocations are never touched here.  Consequently a process restart, or a
    newly deployed configuration file, cannot revive a revoked probe.
    """

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            with closing(_connect(path)) as conn:
                # WAL permits readers while the short final import transaction
                # writes, and survives multiple uvicorn worker processes.
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA wal_autocheckpoint=1000")
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in SCHEMA.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    now = int(time.time())
                    for probe in probes.values():
                        conn.execute(
                            """
                            INSERT INTO probes(
                                probe_id, public_key_pem, authorized_hosts_json,
                                key_fingerprint, configured_at
                            ) VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(probe_id) DO UPDATE SET
                                public_key_pem=excluded.public_key_pem,
                                authorized_hosts_json=excluded.authorized_hosts_json,
                                key_fingerprint=excluded.key_fingerprint,
                                configured_at=excluded.configured_at
                            """,
                            (
                                probe.probe_id,
                                probe.public_key_pem,
                                json.dumps(
                                    sorted(probe.authorized_hosts),
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                                probe.key_fingerprint,
                                now,
                            ),
                        )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
            return
        except sqlite3.OperationalError as exc:
            last_error = exc
            # A second worker may be creating the WAL/schema at the same time.
            time.sleep(0.15 * (attempt + 1))
    raise RuntimeError(f"无法初始化 SQLite：{last_error}")


def is_revoked(db_path: str | Path, probe_id: str) -> bool:
    with closing(open_read_connection(db_path)) as conn:
        row = conn.execute(
            "SELECT 1 FROM revocations WHERE probe_id = ?", (probe_id,)
        ).fetchone()
    return row is not None


def revoke_probe(db_path: str | Path, probe_id: str) -> dict | None:
    """Irreversibly revoke a probe in one short write transaction.

    The write lock is held only for this small update, never while an import
    is streaming.  Once committed, any import that has not yet acquired its
    own final write transaction is guaranteed to observe the revocation.
    """

    with closing(open_write_connection(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            probe_row = conn.execute(
                "SELECT probe_id FROM probes WHERE probe_id = ?", (probe_id,)
            ).fetchone()
            if probe_row is None:
                conn.rollback()
                return None
            now = int(time.time())
            existing = conn.execute(
                "SELECT revoked_at FROM revocations WHERE probe_id = ?",
                (probe_id,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO revocations(probe_id, revoked_at) VALUES (?, ?)",
                    (probe_id, now),
                )
                already = False
                revoked_at = now
            else:
                already = True
                revoked_at = int(existing["revoked_at"])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {
        "probe_id": probe_id,
        "revoked": True,
        "already_revoked": already,
        "revoked_at": revoked_at,
    }


def list_probes(db_path: str | Path) -> list[dict]:
    with closing(open_read_connection(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT p.probe_id, p.authorized_hosts_json, p.key_fingerprint,
                   r.revoked_at
            FROM probes AS p
            LEFT JOIN revocations AS r ON r.probe_id = p.probe_id
            ORDER BY p.probe_id
            """
        ).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "probe_id": row["probe_id"],
                "authorized_hosts": json.loads(row["authorized_hosts_json"]),
                "key_fingerprint": row["key_fingerprint"],
                "revoked": row["revoked_at"] is not None,
                "revoked_at": row["revoked_at"],
            }
        )
    return result


def count_alerts(db_path: str | Path, *, probe_id: str | None = None) -> int:
    query = "SELECT COUNT(*) AS n FROM alerts"
    params: tuple = ()
    if probe_id:
        query += " WHERE probe_id = ?"
        params = (probe_id,)
    with closing(open_read_connection(db_path)) as conn:
        return int(conn.execute(query, params).fetchone()["n"])


def list_alerts(
    db_path: str | Path,
    *,
    page: int,
    page_size: int,
    probe_id: str | None = None,
) -> tuple[list[dict], int]:
    offset = (page - 1) * page_size
    where = ""
    params: list = []
    if probe_id:
        where = " WHERE probe_id = ?"
        params.append(probe_id)
    with closing(open_read_connection(db_path)) as conn:
        total = int(
            conn.execute(
                "SELECT COUNT(*) AS n FROM alerts" + where, tuple(params)
            ).fetchone()["n"]
        )
        rows = conn.execute(
            """
            SELECT id, batch_id, probe_id, event_id, host, time, rule,
                   imported_at
            FROM alerts
            """
            + where
            + " ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params + [page_size, offset]),
        ).fetchall()
    items = [
        {
            "id": row["id"],
            "batch_id": row["batch_id"],
            "probe_id": row["probe_id"],
            "event_id": row["event_id"],
            "host": row["host"],
            "time": row["time"],
            "rule": row["rule"],
            "imported_at": row["imported_at"],
        }
        for row in rows
    ]
    return items, total


def list_import_batches(
    db_path: str | Path,
    *,
    page: int,
    page_size: int,
) -> tuple[list[dict], int]:
    offset = (page - 1) * page_size
    with closing(open_read_connection(db_path)) as conn:
        total = int(
            conn.execute("SELECT COUNT(*) AS n FROM import_batches").fetchone()["n"]
        )
        rows = conn.execute(
            """
            SELECT batch_id, probe_id, file_name, size_bytes, total_lines,
                   imported_lines, skipped_lines, status, failure_code,
                   failure_message, failure_line, started_at, finished_at
            FROM import_batches
            ORDER BY finished_at DESC, batch_id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()
    return [dict(row) for row in rows], total


def record_failed_import(
    db_path: str | Path,
    *,
    batch_id: str,
    probe_id: str,
    file_name: str | None,
    size_bytes: int,
    total_lines: int,
    imported_lines: int,
    skipped_lines: int,
    failure_code: str,
    failure_message: str,
    failure_line: int | None,
    started_at: int,
) -> None:
    """Best-effort audit row; it is never part of the alert batch itself."""

    now = int(time.time())
    try:
        with closing(open_write_connection(db_path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO import_batches(
                        batch_id, probe_id, file_name, size_bytes, total_lines,
                        imported_lines, skipped_lines, status, failure_code,
                        failure_message, failure_line, started_at, finished_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'failed', ?, ?, ?, ?, ?)
                    ON CONFLICT(batch_id) DO UPDATE SET
                        status='failed',
                        failure_code=excluded.failure_code,
                        failure_message=excluded.failure_message,
                        failure_line=excluded.failure_line,
                        finished_at=excluded.finished_at
                    """,
                    (
                        batch_id,
                        probe_id,
                        (file_name or "")[:255],
                        int(size_bytes),
                        int(total_lines),
                        int(imported_lines),
                        int(skipped_lines),
                        failure_code,
                        str(failure_message)[:500],
                        failure_line,
                        int(started_at),
                        now,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    except Exception:
        logger.exception("无法记录失败导入审计（告警批次仍未写入）")
