"""Streaming JSONL validation, detached RSA-PSS verification and atomic import.

The input file is never loaded into memory as a whole.  A SHA-256 digest is
computed over the original bytes while a fixed-size line splitter parses each
line.  Validated rows go to a separate on-disk staging SQLite database.  Only
after the complete file and its signature are verified is a short business DB
transaction opened to publish the batch.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import BinaryIO, Iterator
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from app.config import ProbeConfig
from app.db import open_write_connection, is_revoked, record_failed_import

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = int(os.environ.get("MAX_EVENTS_BYTES", str(32 * 1024 * 1024)))
MAX_LINE_BYTES = 4096
MAX_SIGNATURE_BYTES = 64 * 1024
SALT_LENGTH = 32
READ_CHUNK_BYTES = 64 * 1024
_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class IngestError(Exception):
    """An expected rejection with a safe, user-visible explanation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line: int | None = None,
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.line = line
        self.status_code = status_code

    def to_detail(self) -> dict:
        detail: dict = {"code": self.code, "message": self.message}
        if self.line is not None:
            detail["line"] = self.line
        return detail


@dataclass
class StreamStats:
    bytes_read: int = 0
    lines: int = 0


@dataclass
class StagedEvent:
    event_id: str
    host: str
    time: int
    rule: str
    fields_json: str
    line_no: int


@dataclass
class ImportResult:
    batch_id: str
    probe_id: str
    total_lines: int
    imported_lines: int
    skipped_lines: int
    size_bytes: int

    def as_dict(self) -> dict:
        return {
            "status": "committed",
            "batch_id": self.batch_id,
            "probe_id": self.probe_id,
            "total_lines": self.total_lines,
            "imported_lines": self.imported_lines,
            "skipped_lines": self.skipped_lines,
            "size_bytes": self.size_bytes,
            "message": "签名与全文件校验通过，整批告警已原子提交。",
        }


class _DuplicateKey(Exception):
    pass


class _NonFiniteNumber(Exception):
    pass


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey(key)
        obj[key] = value
    return obj


def _reject_non_finite(value: str) -> None:
    raise _NonFiniteNumber(value)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _strip_cr(raw: bytes) -> bytes:
    return raw[:-1] if raw.endswith(b"\r") else raw


def _iter_raw_lines(
    stream: BinaryIO,
    digest,
    stats: StreamStats,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> Iterator[bytes]:
    """Yield complete physical lines as bytes while hashing every input byte.

    The pending buffer is bounded by ``max_line_bytes + 1``.  Reading a 32 MiB
    file therefore uses a fixed-size buffer regardless of the number of lines.
    """

    pending = bytearray()
    eof = False
    while not eof:
        chunk = stream.read(READ_CHUNK_BYTES)
        if not chunk:
            eof = True
            break
        stats.bytes_read += len(chunk)
        if stats.bytes_read > max_file_bytes:
            raise IngestError(
                "file_too_large",
                f"JSONL 文件超过 {max_file_bytes // (1024 * 1024)} MiB 上限",
                status_code=413,
            )
        digest.update(chunk)

        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            if newline < 0:
                pending.extend(chunk[start:])
                if len(pending) > max_line_bytes + 1:
                    raise IngestError(
                        "line_too_large",
                        f"第 {stats.lines + 1} 行超过 {max_line_bytes} 字节",
                        line=stats.lines + 1,
                        status_code=413,
                    )
                break
            raw = bytes(pending) + chunk[start:newline]
            pending.clear()
            stats.lines += 1
            yield raw
            start = newline + 1

    if pending:
        stats.lines += 1
        yield bytes(pending)
    elif stats.lines == 0:
        raise IngestError("empty_file", "JSONL 文件为空")


def parse_event(
    raw: bytes,
    *,
    probe: ProbeConfig,
    line_no: int,
) -> StagedEvent:
    content = _strip_cr(raw)
    if len(content) > MAX_LINE_BYTES:
        raise IngestError(
            "line_too_large",
            f"第 {line_no} 行超过 {MAX_LINE_BYTES} 字节",
            line=line_no,
            status_code=413,
        )
    if not content.strip():
        raise IngestError("empty_line", f"第 {line_no} 行为空", line=line_no)

    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IngestError(
            "invalid_utf8", f"第 {line_no} 行不是有效的 UTF-8：{exc.reason}", line=line_no
        ) from exc

    try:
        record = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_non_finite,
        )
    except _DuplicateKey as exc:
        raise IngestError(
            "duplicate_json_key",
            f"第 {line_no} 行包含重复字段：{exc.args[0]}",
            line=line_no,
        ) from exc
    except _NonFiniteNumber as exc:
        raise IngestError(
            "invalid_json", f"第 {line_no} 行包含不允许的 NaN/Infinity", line=line_no
        ) from exc
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise IngestError(
            "invalid_json",
            f"第 {line_no} 行不是有效的 JSON：{exc.msg if hasattr(exc, 'msg') else '语法错误'}",
            line=line_no,
        ) from exc

    if not isinstance(record, dict):
        raise IngestError("invalid_json", f"第 {line_no} 行必须是 JSON 对象", line=line_no)

    for field in ("probe_id", "event_id", "host", "time", "rule"):
        if field not in record:
            raise IngestError(
                "missing_field",
                f"第 {line_no} 行缺少字段 {field}",
                line=line_no,
            )

    submitted_probe = record["probe_id"]
    if not isinstance(submitted_probe, str) or not submitted_probe:
        raise IngestError(
            "invalid_field",
            f"第 {line_no} 行 probe_id 必须是非空字符串",
            line=line_no,
        )
    if submitted_probe != probe.probe_id:
        raise IngestError(
            "probe_mismatch",
            f"第 {line_no} 行 probe_id 与所选探针不一致",
            line=line_no,
        )

    host = record["host"]
    if not isinstance(host, str) or not host:
        raise IngestError(
            "invalid_field", f"第 {line_no} 行 host 必须是非空字符串", line=line_no
        )
    if host not in probe.authorized_hosts:
        raise IngestError(
            "host_unauthorized",
            f"第 {line_no} 行主机 {host!r} 不在探针 {probe.probe_id} 的授权范围内",
            line=line_no,
            status_code=403,
        )

    event_time = record["time"]
    if (
        not isinstance(event_time, int)
        or isinstance(event_time, bool)
        or event_time < _INT64_MIN
        or event_time > _INT64_MAX
    ):
        raise IngestError(
            "invalid_field",
            f"第 {line_no} 行 time 必须是 UTC 整数秒（64 位有符号整数）",
            line=line_no,
        )

    rule = record["rule"]
    if not isinstance(rule, str):
        raise IngestError(
            "invalid_field", f"第 {line_no} 行 rule 必须是字符串", line=line_no
        )

    raw_event_id = record["event_id"]
    if isinstance(raw_event_id, str):
        if not raw_event_id:
            raise IngestError(
                "invalid_field",
                f"第 {line_no} 行 event_id 必须是非空字符串",
                line=line_no,
            )
        event_id = raw_event_id
    elif isinstance(raw_event_id, int) and not isinstance(raw_event_id, bool):
        if raw_event_id < _INT64_MIN or raw_event_id > _INT64_MAX:
            raise IngestError(
                "invalid_field", f"第 {line_no} 行 event_id 超出 64 位整数范围", line=line_no
            )
        event_id = str(raw_event_id)
    else:
        raise IngestError(
            "invalid_field",
            f"第 {line_no} 行 event_id 必须是字符串或整数",
            line=line_no,
        )
    # Uniqueness follows the event_id text.  An integer ID and the same
    # textual ID denote the same event; the full fields comparison below
    # still detects the type difference as a conflicting duplicate.

    try:
        fields_json = _canonical(record)
    except (TypeError, ValueError) as exc:
        raise IngestError(
            "invalid_json", f"第 {line_no} 行包含无法规范化的值", line=line_no
        ) from exc
    try:
        fields_json.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IngestError(
            "invalid_unicode",
            f"第 {line_no} 行包含无效的 Unicode 代理项",
            line=line_no,
        ) from exc

    return StagedEvent(
        event_id=event_id,
        host=host,
        time=event_time,
        rule=rule,
        fields_json=fields_json,
        line_no=line_no,
    )


def _decode_signature(raw: bytes) -> bytes:
    if not raw:
        raise IngestError("signature_missing", "独立签名文件为空", status_code=400)
    if len(raw) > MAX_SIGNATURE_BYTES:
        raise IngestError("signature_too_large", "签名文件过大", status_code=413)

    stripped = raw.strip()
    if stripped.startswith(b"-----BEGIN") or stripped.startswith(b"-----END"):
        payload = b"".join(
            line.strip()
            for line in stripped.splitlines()
            if not line.strip().startswith(b"-----")
        )
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise IngestError("signature_invalid", "签名 PEM/base64 无法解码") from exc
        if len(decoded) > MAX_SIGNATURE_BYTES:
            raise IngestError("signature_too_large", "签名解码后过大", status_code=413)
        return decoded

    single_line = b"".join(stripped.split())
    if single_line and len(single_line) >= 64 and _BASE64_RE.fullmatch(single_line):
        try:
            decoded = base64.b64decode(single_line, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise IngestError("signature_invalid", "签名 base64 无法解码") from exc
        if len(decoded) <= MAX_SIGNATURE_BYTES:
            return decoded
    return raw


def verify_signature(
    probe: ProbeConfig,
    signature_raw: bytes,
    digest: bytes,
) -> None:
    signature = _decode_signature(signature_raw)
    key = probe.public_key
    if not isinstance(key, rsa.RSAPublicKey):
        raise IngestError("probe_key_invalid", "探针公钥不是 RSA 公钥", status_code=500)
    try:
        key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LENGTH),
            Prehashed(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise IngestError(
            "signature_invalid",
            "RSA-PSS/SHA256 签名校验失败（文件可能被篡改或签名不匹配）",
            status_code=400,
        ) from exc
    except (ValueError, TypeError) as exc:
        raise IngestError(
            "signature_invalid", "签名格式无效，无法进行 RSA-PSS 校验", status_code=400
        ) from exc


def _create_stage(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA cache_size=-2048")
    conn.execute(
        """
        CREATE TABLE staged (
            event_id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            event_time INTEGER NOT NULL,
            rule TEXT NOT NULL,
            fields_json TEXT NOT NULL,
            line_no INTEGER NOT NULL
        ) WITHOUT ROWID
        """
    )
    # Batch all staging inserts into one transaction.  The staging database
    # is disposable and lives outside the business DB; this only removes
    # per-row transaction overhead.
    conn.execute("BEGIN")
    return conn


def _stage_event(
    conn: sqlite3.Connection,
    event: StagedEvent,
) -> bool:
    """Return True when the event is new; False for an identical duplicate."""

    try:
        conn.execute(
            """
            INSERT INTO staged(
                event_id, host, event_time, rule, fields_json, line_no
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.host,
                event.time,
                event.rule,
                event.fields_json,
                event.line_no,
            ),
        )
        return True
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT fields_json, line_no FROM staged WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if row is not None and row[0] == event.fields_json:
            return False
        original_line = int(row[1]) if row is not None else None
        raise IngestError(
            "duplicate_conflict",
            (
                f"第 {event.line_no} 行与第 {original_line} 行的同探针 event_id "
                "字段内容不一致，整批拒绝"
            ),
            line=event.line_no,
            status_code=409,
        )


def _commit_staged(
    *,
    db_path: str | Path,
    stage_path: Path,
    probe: ProbeConfig,
    batch_id: str,
    file_name: str | None,
    stats: StreamStats,
    started_at: int,
) -> ImportResult:
    """Copy staged rows in one short write transaction.

    Acquiring ``BEGIN IMMEDIATE`` is the revocation barrier: either this
    transaction is already the writer (and the import is committed before a
    later revocation can succeed), or a revocation committed first and the
    import observes it here and aborts without publishing any row.
    """

    with sqlite3.connect(
        str(db_path), timeout=30, isolation_level=None
    ) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA temp_store=FILE")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            conn.execute("ATTACH DATABASE ? AS staging", (str(stage_path),))
        except sqlite3.OperationalError as exc:
            raise IngestError(
                "staging_unavailable", "无法打开导入暂存区", status_code=500
            ) from exc

        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise IngestError(
                    "storage_busy", "告警库写事务繁忙，请稍后重新导入", status_code=503
                ) from exc
            raise

        try:
            revoked = conn.execute(
                "SELECT 1 FROM revocations WHERE probe_id = ?",
                (probe.probe_id,),
            ).fetchone()
            if revoked is not None:
                raise IngestError(
                    "probe_revoked",
                    f"探针 {probe.probe_id} 已被撤销，未提交的导入整批拒绝",
                    status_code=409,
                )

            # Whole-file duplicate checks are performed against the committed
            # alerts while holding the writer lock.  No concurrent writer can
            # race this comparison.
            conflict = conn.execute(
                """
                SELECT s.line_no
                FROM staging.staged AS s
                JOIN alerts AS a
                  ON a.probe_id = ? AND a.event_id = s.event_id
                WHERE a.fields_json <> s.fields_json
                ORDER BY s.line_no
                LIMIT 1
                """,
                (probe.probe_id,),
            ).fetchone()
            if conflict is not None:
                raise IngestError(
                    "duplicate_conflict",
                    (
                        f"第 {conflict['line_no']} 行的 event_id 已存在且字段内容不同，"
                        "整批拒绝"
                    ),
                    line=int(conflict["line_no"]),
                    status_code=409,
                )

            before_changes = conn.total_changes
            conn.execute(
                """
                INSERT INTO alerts(
                    batch_id, probe_id, event_id, host,
                    time, rule, fields_json, imported_at
                )
                SELECT ?, ?, s.event_id, s.host,
                       s.event_time, s.rule, s.fields_json, ?
                FROM staging.staged AS s
                WHERE NOT EXISTS (
                    SELECT 1 FROM alerts AS a
                    WHERE a.probe_id = ? AND a.event_id = s.event_id
                )
                """,
                (
                    batch_id,
                    probe.probe_id,
                    started_at,
                    probe.probe_id,
                ),
            )
            imported_lines = int(conn.total_changes - before_changes)
            skipped_lines = stats.lines - imported_lines

            conn.execute(
                """
                INSERT INTO import_batches(
                    batch_id, probe_id, file_name, size_bytes, total_lines,
                    imported_lines, skipped_lines, status, failure_code,
                    failure_message, failure_line, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'committed', NULL, NULL, NULL, ?, ?)
                """,
                (
                    batch_id,
                    probe.probe_id,
                    (file_name or "")[:255],
                    int(stats.bytes_read),
                    int(stats.lines),
                    imported_lines,
                    skipped_lines,
                    int(started_at),
                    int(time.time()),
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            try:
                conn.execute("DETACH DATABASE staging")
            except sqlite3.Error:
                pass

    return ImportResult(
        batch_id=batch_id,
        probe_id=probe.probe_id,
        total_lines=stats.lines,
        imported_lines=imported_lines,
        skipped_lines=skipped_lines,
        size_bytes=stats.bytes_read,
    )


def ingest_batch(
    *,
    db_path: str | Path,
    staging_dir: str | Path,
    probe: ProbeConfig,
    events_file: BinaryIO,
    signature_raw: bytes,
    file_name: str | None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> ImportResult:
    """Validate, verify and atomically import one signed JSONL batch."""

    started_at = int(time.time())
    batch_id = uuid4().hex
    stats = StreamStats()
    staging_root = Path(staging_dir)
    staging_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="probe-import-", dir=str(staging_root)))
    stage_path = work_dir / "staged.sqlite3"
    stage_conn: sqlite3.Connection | None = None
    digest = hashlib.sha256()

    try:
        if is_revoked(db_path, probe.probe_id):
            raise IngestError(
                "probe_revoked",
                f"探针 {probe.probe_id} 已被撤销，不能接收告警",
                status_code=409,
            )

        stage_conn = _create_stage(stage_path)
        try:
            events_file.seek(0)
        except (OSError, AttributeError):
            pass

        for line_no, raw in enumerate(
            _iter_raw_lines(
                events_file,
                digest,
                stats,
                max_file_bytes=max_file_bytes,
                max_line_bytes=MAX_LINE_BYTES,
            ),
            start=1,
        ):
            event = parse_event(raw, probe=probe, line_no=line_no)
            _stage_event(stage_conn, event)

        stage_conn.commit()
        stage_conn.close()
        stage_conn = None

        verify_signature(probe, signature_raw, digest.digest())
        result = _commit_staged(
            db_path=db_path,
            stage_path=stage_path,
            probe=probe,
            batch_id=batch_id,
            file_name=file_name,
            stats=stats,
            started_at=started_at,
        )
        return result

    except IngestError as exc:
        record_failed_import(
            db_path,
            batch_id=batch_id,
            probe_id=probe.probe_id,
            file_name=file_name,
            size_bytes=stats.bytes_read,
            total_lines=stats.lines,
            imported_lines=0,
            skipped_lines=0,
            failure_code=exc.code,
            failure_message=exc.message,
            failure_line=exc.line,
            started_at=started_at,
        )
        raise
    except Exception as exc:
        logger.exception("导入处理内部错误")
        record_failed_import(
            db_path,
            batch_id=batch_id,
            probe_id=probe.probe_id,
            file_name=file_name,
            size_bytes=stats.bytes_read,
            total_lines=stats.lines,
            imported_lines=0,
            skipped_lines=0,
            failure_code="ingest_internal_error",
            failure_message=f"导入处理失败：{type(exc).__name__}",
            failure_line=None,
            started_at=started_at,
        )
        raise IngestError(
            "ingest_internal_error",
            "导入处理内部错误，未写入任何告警",
            status_code=500,
        ) from exc
    finally:
        if stage_conn is not None:
            try:
                stage_conn.close()
            except sqlite3.Error:
                pass
        shutil.rmtree(work_dir, ignore_errors=True)
