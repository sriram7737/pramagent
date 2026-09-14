"""Distributed PostgreSQL outbox for external evidence anchors."""
from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .._pg import connect as pg_connect
from .anchors import AnchorJob, SigstoreAnchorProvider
from .evidence_v2 import ExternalAnchorV2, SignedCheckpointV2, canonicalize_jcs

__all__ = ["AnchorLeaseLostError", "PostgresAnchorOutbox"]

_SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,47}$")


class AnchorLeaseLostError(RuntimeError):
    """Raised when an expired worker attempts to overwrite a newer lease."""


class PostgresAnchorOutbox:
    """Multi-worker anchor queue using transactional claims and lease fencing.

    Delivery is at least once because a worker can fail after an external
    service accepts a request but before PostgreSQL records the receipt. The
    lease token prevents that stale worker from overwriting a later worker's
    result, and the stored anchor map keeps one authoritative artifact for
    each anchor type.
    """

    def __init__(
        self,
        dsn: str,
        *,
        table: str = "pramagent_evidence_anchor_jobs",
        connect_factory: Callable[[str], Any] | None = None,
    ) -> None:
        if not dsn or not str(dsn).strip():
            raise ValueError("Postgres anchor outbox DSN is required")
        if not _SAFE_NAME.fullmatch(table):
            raise ValueError(f"unsafe table name: {table!r}")
        self.dsn = str(dsn)
        self.table = table
        self._connect_factory = connect_factory or pg_connect
        self._run(self._create_schema)

    def close(self) -> None:
        """Connections are transaction-scoped, so there is nothing to close."""

    def __enter__(self) -> "PostgresAnchorOutbox":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _run(self, operation: Callable[[Any], Any]) -> Any:
        connection = self._connect_factory(self.dsn)
        try:
            with connection.cursor() as cursor:
                result = operation(cursor)
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, cursor: Any) -> None:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                checkpoint_hash TEXT PRIMARY KEY,
                checkpoint_json JSONB NOT NULL,
                anchors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                status TEXT NOT NULL CHECK (
                    status IN ('queued', 'retry', 'running', 'complete')
                ),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at_us BIGINT NOT NULL,
                locked_until_us BIGINT NOT NULL DEFAULT 0,
                lease_id TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                updated_at_us BIGINT NOT NULL
            )
            """
        )
        cursor.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{self.table}_due
            ON {self.table} (status, next_attempt_at_us, locked_until_us)
            """
        )

    @staticmethod
    def _json_value(value: Any) -> Any:
        return json.loads(value) if isinstance(value, str) else value

    @staticmethod
    def _rowdict(cursor: Any, row: Any) -> dict[str, Any] | None:
        if row is None:
            return None
        if isinstance(row, Mapping):
            return dict(row)
        columns = [item[0] for item in cursor.description]
        return dict(zip(columns, row))

    @staticmethod
    def _anchors(value: Any) -> dict[str, ExternalAnchorV2]:
        return {
            anchor.anchor_type: anchor
            for anchor in (
                ExternalAnchorV2.from_dict(item)
                for item in PostgresAnchorOutbox._json_value(value)
            )
        }

    @staticmethod
    def _encoded_anchors(anchors: Mapping[str, ExternalAnchorV2]) -> str:
        return canonicalize_jcs(
            [anchors[key].to_dict() for key in sorted(anchors)]
        ).decode("utf-8")

    def enqueue(
        self, checkpoint: SignedCheckpointV2, *, now_us: int | None = None
    ) -> None:
        checkpoint.validate()
        current = now_us if now_us is not None else time.time_ns() // 1_000
        encoded = canonicalize_jcs(checkpoint.to_dict()).decode("utf-8")

        def operation(cursor: Any) -> None:
            cursor.execute(
                f"""
                INSERT INTO {self.table} (
                    checkpoint_hash, checkpoint_json, status,
                    next_attempt_at_us, updated_at_us
                ) VALUES (%s, %s::jsonb, 'queued', %s, %s)
                ON CONFLICT (checkpoint_hash) DO NOTHING
                """,
                (checkpoint.checkpoint_hash, encoded, current, current),
            )

        self._run(operation)

    def get(self, checkpoint_hash: str) -> AnchorJob | None:
        def operation(cursor: Any) -> AnchorJob | None:
            cursor.execute(
                f"""
                SELECT checkpoint_hash, status, attempts, next_attempt_at_us,
                       last_error, anchors_json
                FROM {self.table}
                WHERE checkpoint_hash = %s
                """,
                (checkpoint_hash,),
            )
            row = self._rowdict(cursor, cursor.fetchone())
            if row is None:
                return None
            anchors = self._anchors(row["anchors_json"])
            return AnchorJob(
                checkpoint_hash=row["checkpoint_hash"],
                status=row["status"],
                attempts=int(row["attempts"]),
                next_attempt_at_us=int(row["next_attempt_at_us"]),
                last_error=row["last_error"],
                anchors=tuple(anchors[key] for key in sorted(anchors)),
            )

        return self._run(operation)

    def process_one(
        self,
        provider: SigstoreAnchorProvider,
        *,
        now_us: int | None = None,
        lease_seconds: int = 60,
    ) -> AnchorJob | None:
        """Process one due checkpoint and retain successful partial work."""
        current = now_us if now_us is not None else time.time_ns() // 1_000
        row = self._claim(current, lease_seconds)
        if row is None:
            return None
        checkpoint_hash = row["checkpoint_hash"]
        lease_id = row["lease_id"]
        checkpoint = SignedCheckpointV2.from_dict(
            self._json_value(row["checkpoint_json"])
        )
        anchors = self._anchors(row["anchors_json"])
        try:
            if "RFC3161" not in anchors:
                anchors["RFC3161"] = provider.issue_rfc3161(checkpoint)
                self._save_progress(checkpoint_hash, lease_id, anchors, current)
            if "transparency-log" not in anchors:
                anchors["transparency-log"] = provider.publish_transparency(
                    checkpoint
                )
                self._save_progress(checkpoint_hash, lease_id, anchors, current)
        except AnchorLeaseLostError:
            raise
        except Exception as exc:
            attempts = int(row["attempts"]) + 1
            delay_seconds = min(3600, 2 ** min(attempts, 11))
            self._finish(
                checkpoint_hash,
                lease_id=lease_id,
                status="retry",
                attempts=attempts,
                next_attempt_at_us=current + delay_seconds * 1_000_000,
                last_error=str(exc),
                anchors=anchors,
                now_us=current,
            )
            return self.get(checkpoint_hash)
        self._finish(
            checkpoint_hash,
            lease_id=lease_id,
            status="complete",
            attempts=int(row["attempts"]) + 1,
            next_attempt_at_us=current,
            last_error="",
            anchors=anchors,
            now_us=current,
        )
        return self.get(checkpoint_hash)

    def _claim(self, now_us: int, lease_seconds: int) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        lease_id = uuid.uuid4().hex
        locked_until = now_us + lease_seconds * 1_000_000

        def operation(cursor: Any) -> dict[str, Any] | None:
            cursor.execute(
                f"""
                WITH candidate AS (
                    SELECT checkpoint_hash
                    FROM {self.table}
                    WHERE status IN ('queued', 'retry', 'running')
                      AND next_attempt_at_us <= %s
                      AND (status != 'running' OR locked_until_us <= %s)
                    ORDER BY next_attempt_at_us, checkpoint_hash
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE {self.table} AS jobs
                SET status = 'running', locked_until_us = %s,
                    lease_id = %s, updated_at_us = %s
                FROM candidate
                WHERE jobs.checkpoint_hash = candidate.checkpoint_hash
                RETURNING jobs.checkpoint_hash, jobs.checkpoint_json,
                          jobs.anchors_json, jobs.status, jobs.attempts,
                          jobs.next_attempt_at_us, jobs.locked_until_us,
                          jobs.lease_id, jobs.last_error, jobs.updated_at_us
                """,
                (now_us, now_us, locked_until, lease_id, now_us),
            )
            return self._rowdict(cursor, cursor.fetchone())

        return self._run(operation)

    def _save_progress(
        self,
        checkpoint_hash: str,
        lease_id: str,
        anchors: Mapping[str, ExternalAnchorV2],
        now_us: int,
    ) -> None:
        encoded = self._encoded_anchors(anchors)

        def operation(cursor: Any) -> int:
            cursor.execute(
                f"""
                UPDATE {self.table}
                SET anchors_json = %s::jsonb, updated_at_us = %s
                WHERE checkpoint_hash = %s AND status = 'running'
                  AND lease_id = %s
                """,
                (encoded, now_us, checkpoint_hash, lease_id),
            )
            return cursor.rowcount

        if self._run(operation) != 1:
            raise AnchorLeaseLostError(
                f"anchor lease lost for checkpoint {checkpoint_hash}"
            )

    def _finish(
        self,
        checkpoint_hash: str,
        *,
        lease_id: str,
        status: str,
        attempts: int,
        next_attempt_at_us: int,
        last_error: str,
        anchors: Mapping[str, ExternalAnchorV2],
        now_us: int,
    ) -> None:
        if status not in {"retry", "complete"}:
            raise ValueError("anchor job can finish only as retry or complete")
        encoded = self._encoded_anchors(anchors)

        def operation(cursor: Any) -> int:
            cursor.execute(
                f"""
                UPDATE {self.table}
                SET anchors_json = %s::jsonb, status = %s, attempts = %s,
                    next_attempt_at_us = %s, locked_until_us = 0,
                    lease_id = '', last_error = %s, updated_at_us = %s
                WHERE checkpoint_hash = %s AND status = 'running'
                  AND lease_id = %s
                """,
                (
                    encoded,
                    status,
                    attempts,
                    next_attempt_at_us,
                    last_error[:2000],
                    now_us,
                    checkpoint_hash,
                    lease_id,
                ),
            )
            return cursor.rowcount

        if self._run(operation) != 1:
            raise AnchorLeaseLostError(
                f"anchor lease lost for checkpoint {checkpoint_hash}"
            )
