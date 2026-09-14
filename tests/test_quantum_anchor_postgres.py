from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("pqcrypto")
pytest.importorskip("rfc8785")

from pramagent.quantum import (
    AnchorLeaseLostError,
    AnchorOutboxBackend,
    ExternalAnchorV2,
    HybridCheckpointSigner,
    MerkleEpochBuilder,
    PostgresAnchorOutbox,
)


def _checkpoint():
    signer = HybridCheckpointSigner.generate(
        ed25519_key_id="postgres-anchor-ed",
        ml_dsa_65_key_id="postgres-anchor-pq",
    )
    builder = MerkleEpochBuilder()
    now_us = time.time_ns() // 1_000
    builder.append_native(
        record_id="postgres-anchor-record",
        observed_at_us=now_us,
        record={"record_version": "2.0", "event": "anchor_test"},
        nonce=b"postgres-anchor!",
    )
    return builder.sign_checkpoint(
        epoch_id="postgres-anchor-epoch",
        issued_at_us=now_us,
        signer=signer,
    )


def _anchor(checkpoint_hash: str, anchor_type: str) -> ExternalAnchorV2:
    return ExternalAnchorV2(
        anchor_type=anchor_type,
        witness_id=f"https://{anchor_type}.example.test",
        checkpoint_hash=checkpoint_hash,
        issued_at_us=time.time_ns() // 1_000,
        artifact_b64=base64.b64encode(b"artifact").decode(),
        anchor_id=f"{anchor_type}-id",
    )


@dataclass
class _FakeDB:
    rows: dict[str, dict] = field(default_factory=dict)
    statements: list[str] = field(default_factory=list)


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.rowcount = 0
        self.description = []
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        statement = " ".join(str(sql).lower().split())
        params = tuple(params or ())
        self.db.statements.append(statement)
        self.rowcount = 0
        self._row = None
        self.description = []
        if statement.startswith("create table") or statement.startswith(
            "create index"
        ):
            return
        if statement.startswith("insert into"):
            checkpoint_hash, checkpoint_json, next_attempt, updated_at = params
            if checkpoint_hash not in self.db.rows:
                self.db.rows[checkpoint_hash] = {
                    "checkpoint_hash": checkpoint_hash,
                    "checkpoint_json": checkpoint_json,
                    "anchors_json": "[]",
                    "status": "queued",
                    "attempts": 0,
                    "next_attempt_at_us": next_attempt,
                    "locked_until_us": 0,
                    "lease_id": "",
                    "last_error": "",
                    "updated_at_us": updated_at,
                }
                self.rowcount = 1
            return
        if statement.startswith("with candidate as"):
            now_us, _, locked_until, lease_id, updated_at = params
            candidates = [
                row
                for row in self.db.rows.values()
                if row["status"] in {"queued", "retry", "running"}
                and row["next_attempt_at_us"] <= now_us
                and (
                    row["status"] != "running"
                    or row["locked_until_us"] <= now_us
                )
            ]
            if candidates:
                row = sorted(
                    candidates,
                    key=lambda item: (
                        item["next_attempt_at_us"],
                        item["checkpoint_hash"],
                    ),
                )[0]
                row.update(
                    status="running",
                    locked_until_us=locked_until,
                    lease_id=lease_id,
                    updated_at_us=updated_at,
                )
                columns = [
                    "checkpoint_hash",
                    "checkpoint_json",
                    "anchors_json",
                    "status",
                    "attempts",
                    "next_attempt_at_us",
                    "locked_until_us",
                    "lease_id",
                    "last_error",
                    "updated_at_us",
                ]
                self.description = [(name,) for name in columns]
                self._row = tuple(row[name] for name in columns)
                self.rowcount = 1
            return
        if statement.startswith("select checkpoint_hash, status"):
            row = self.db.rows.get(params[0])
            if row:
                columns = [
                    "checkpoint_hash",
                    "status",
                    "attempts",
                    "next_attempt_at_us",
                    "last_error",
                    "anchors_json",
                ]
                self.description = [(name,) for name in columns]
                self._row = tuple(row[name] for name in columns)
            return
        if "set anchors_json" in statement and "status = %s" not in statement:
            encoded, updated_at, checkpoint_hash, lease_id = params
            row = self.db.rows.get(checkpoint_hash)
            if row and row["status"] == "running" and row["lease_id"] == lease_id:
                row.update(anchors_json=encoded, updated_at_us=updated_at)
                self.rowcount = 1
            return
        if "set anchors_json" in statement and "status = %s" in statement:
            (
                encoded,
                status,
                attempts,
                next_attempt,
                last_error,
                updated_at,
                checkpoint_hash,
                lease_id,
            ) = params
            row = self.db.rows.get(checkpoint_hash)
            if row and row["status"] == "running" and row["lease_id"] == lease_id:
                row.update(
                    anchors_json=encoded,
                    status=status,
                    attempts=attempts,
                    next_attempt_at_us=next_attempt,
                    locked_until_us=0,
                    lease_id="",
                    last_error=last_error,
                    updated_at_us=updated_at,
                )
                self.rowcount = 1
            return
        raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self, db: _FakeDB):
        self.db = db

    def cursor(self):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def outbox():
    db = _FakeDB()
    value = PostgresAnchorOutbox(
        "postgresql://unit-test",
        connect_factory=lambda _dsn: _FakeConnection(db),
    )
    return value, db


def test_postgres_outbox_implements_contract_and_uses_skip_locked(outbox):
    value, db = outbox
    checkpoint = _checkpoint()
    value.enqueue(checkpoint, now_us=100)

    claimed = value._claim(100, lease_seconds=10)

    assert isinstance(value, AnchorOutboxBackend)
    assert claimed is not None
    assert any("for update skip locked" in sql for sql in db.statements)


def test_postgres_outbox_completes_and_enqueue_is_idempotent(outbox):
    value, db = outbox
    checkpoint = _checkpoint()

    class Provider:
        def issue_rfc3161(self, signed):
            return _anchor(signed.checkpoint_hash, "RFC3161")

        def publish_transparency(self, signed):
            return _anchor(signed.checkpoint_hash, "transparency-log")

    value.enqueue(checkpoint, now_us=100)
    value.enqueue(checkpoint, now_us=200)
    result = value.process_one(Provider(), now_us=100)

    assert len(db.rows) == 1
    assert result is not None
    assert result.status == "complete"
    assert result.attempts == 1
    assert [item.anchor_type for item in result.anchors] == [
        "RFC3161",
        "transparency-log",
    ]


def test_postgres_outbox_retains_partial_anchor_across_retry(outbox):
    value, _ = outbox
    checkpoint = _checkpoint()

    class Provider:
        def __init__(self):
            self.tsa_calls = 0
            self.log_calls = 0

        def issue_rfc3161(self, signed):
            self.tsa_calls += 1
            return _anchor(signed.checkpoint_hash, "RFC3161")

        def publish_transparency(self, signed):
            self.log_calls += 1
            if self.log_calls == 1:
                raise RuntimeError("temporary transparency outage")
            return _anchor(signed.checkpoint_hash, "transparency-log")

    provider = Provider()
    value.enqueue(checkpoint, now_us=100)
    first = value.process_one(provider, now_us=100)
    assert first is not None and first.status == "retry"
    assert [item.anchor_type for item in first.anchors] == ["RFC3161"]

    second = value.process_one(provider, now_us=first.next_attempt_at_us)
    assert second is not None and second.status == "complete"
    assert provider.tsa_calls == 1
    assert provider.log_calls == 2


def test_postgres_outbox_fences_worker_after_lease_reassignment(outbox):
    value, db = outbox
    checkpoint = _checkpoint()
    value.enqueue(checkpoint, now_us=100)
    first = value._claim(100, lease_seconds=10)
    assert first is not None
    assert value._claim(101, lease_seconds=10) is None

    second = value._claim(10_000_101, lease_seconds=10)
    assert second is not None
    assert second["lease_id"] != first["lease_id"]

    with pytest.raises(AnchorLeaseLostError, match="lease lost"):
        value._finish(
            checkpoint.checkpoint_hash,
            lease_id=first["lease_id"],
            status="complete",
            attempts=1,
            next_attempt_at_us=10_000_101,
            last_error="",
            anchors={},
            now_us=10_000_101,
        )
    assert db.rows[checkpoint.checkpoint_hash]["lease_id"] == second["lease_id"]


def test_postgres_outbox_rejects_unsafe_table_before_connecting():
    called = False

    def connect(_dsn):
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="unsafe table"):
        PostgresAnchorOutbox(
            "postgresql://unit-test",
            table="anchors;drop",
            connect_factory=connect,
        )
    assert called is False
