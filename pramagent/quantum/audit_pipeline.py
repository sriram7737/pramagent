"""Durable V2 evidence production for ordinary Pramagent audit events.

``V2AuditBackend`` decorates any normal :class:`~pramagent.audit.AuditBackend`.
It preserves the existing hash-chain write, then records an integer-safe V2 leaf
bound to that completed chain link.  Epoch signing and external anchoring are
deliberately separate maintenance operations: an external witness outage never
holds up a tool decision.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..audit import AuditAppendResult
from .anchors import AnchorOutboxBackend, SigstoreAnchorProvider, attach_anchors
from .evidence_v2 import (
    AssuranceLevel,
    EvidenceEnvelopeV2,
    EvidenceLeafV2,
    EvidenceV2Error,
    HybridCheckpointSigner,
    SignedCheckpointV2,
)
from .merkle import MerkleEpochBuilder


def _now_us() -> int:
    return time.time_ns() // 1_000


@dataclass(frozen=True)
class EvidencePipelineAppend:
    """The V2 leaf created for one completed audit-chain append."""

    leaf: EvidenceLeafV2
    checkpoint_hash: str | None = None


class AuditEvidencePipeline:
    """Persist V2 leaves, periodically close signed epochs, and queue anchors.

    The pipeline owns a small SQLite journal so leaf nonces, unsigned leaves,
    and signed checkpoints survive process restarts.  It does not contact a
    TSA or transparency log from ``record_audit_append``.  Invoke
    :meth:`run_maintenance` from a scheduler/worker to close aged epochs and
    process due outbox work.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        signer: HybridCheckpointSigner,
        outbox: AnchorOutboxBackend,
        epoch_max_leaves: int = 1_000,
        epoch_max_age_s: int = 300,
        source_assurance: AssuranceLevel = AssuranceLevel.CHECKSUM_ONLY,
        clock_us: Callable[[], int] = _now_us,
    ) -> None:
        if epoch_max_leaves < 1:
            raise ValueError("epoch_max_leaves must be positive")
        if epoch_max_age_s < 1:
            raise ValueError("epoch_max_age_s must be positive")
        if source_assurance not in {
            AssuranceLevel.CHECKSUM_ONLY,
            AssuranceLevel.HMAC_AUTHENTICATED,
        }:
            raise ValueError("audit source assurance must be checksum or HMAC")
        resolved = Path(path).expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.path = resolved
        self.signer = signer
        self.outbox = outbox
        self.epoch_max_leaves = epoch_max_leaves
        self.epoch_max_age_us = epoch_max_age_s * 1_000_000
        self.source_assurance = source_assurance
        self._clock_us = clock_us
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(resolved), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AuditEvidencePipeline":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_pipeline_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    active_started_at_us INTEGER NOT NULL,
                    next_sequence INTEGER NOT NULL,
                    previous_checkpoint_json TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS evidence_pipeline_active_entries (
                    sequence INTEGER PRIMARY KEY,
                    leaf_json TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_pipeline_epochs (
                    checkpoint_hash TEXT PRIMARY KEY,
                    checkpoint_json TEXT NOT NULL,
                    closed_at_us INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_pipeline_envelopes (
                    record_id TEXT PRIMARY KEY,
                    checkpoint_hash TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    FOREIGN KEY(checkpoint_hash)
                        REFERENCES evidence_pipeline_epochs(checkpoint_hash)
                );
                """
            )
            row = self._conn.execute(
                "SELECT singleton FROM evidence_pipeline_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO evidence_pipeline_state (
                        singleton, active_started_at_us, next_sequence,
                        previous_checkpoint_json
                    ) VALUES (1, ?, 0, '')
                    """,
                    (self._clock_us(),),
                )

    @staticmethod
    def _encoded(value: dict) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _state(self) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM evidence_pipeline_state WHERE singleton = 1"
        ).fetchone()
        if row is None:  # pragma: no cover - schema invariant
            raise RuntimeError("evidence pipeline state is missing")
        return row

    def _builder(self, start_sequence: int) -> MerkleEpochBuilder:
        builder = MerkleEpochBuilder(start_sequence=start_sequence)
        rows = self._conn.execute(
            "SELECT leaf_json, record_json FROM evidence_pipeline_active_entries "
            "ORDER BY sequence"
        ).fetchall()
        snapshot = {
            "snapshot_version": "1",
            "start_sequence": start_sequence,
            "entries": [
                {
                    "leaf": json.loads(row["leaf_json"]),
                    "record": json.loads(row["record_json"]),
                }
                for row in rows
            ],
        }
        return MerkleEpochBuilder.from_dict(snapshot)

    @staticmethod
    def _audit_record(payload: dict[str, Any], result: AuditAppendResult) -> dict[str, Any]:
        """Make a V2-safe projection bound to the pre-existing audit link.

        Raw traces may contain floating point latency fields and scrubbed user
        text.  The audit-chain hash already binds those bytes; the V2 record
        carries that immutable reference plus non-sensitive routing metadata.
        """
        return {
            "audit_anchor_id": str(result.anchor_tx_id),
            "audit_chain_hash": result.this_hash,
            "audit_prev_hash": result.prev_hash,
            "event_kind": str(
                payload.get("source")
                or payload.get("action")
                or payload.get("action_label")
                or "trace"
            ),
            "record_type": "pramagent-audit-link-v1",
            "session_id": str(payload.get("session_id", "default")),
            "tenant_id": str(payload.get("tenant_id", "default")),
        }

    def record_audit_append(
        self, payload: dict[str, Any], result: AuditAppendResult
    ) -> EvidencePipelineAppend:
        """Persist one leaf after the wrapped audit backend accepted an event."""
        if not isinstance(payload, dict):
            raise TypeError("audit payload must be a dictionary")
        current = self._clock_us()
        record = self._audit_record(payload, result)
        with self._lock, self._conn:
            state = self._state()
            builder = self._builder(int(state["next_sequence"]))
            leaf = builder.append_native(
                record_id=result.this_hash,
                observed_at_us=current,
                record=record,
                source_assurance=self.source_assurance,
            )
            self._conn.execute(
                """
                INSERT INTO evidence_pipeline_active_entries (sequence, leaf_json, record_json)
                VALUES (?, ?, ?)
                """,
                (leaf.sequence, self._encoded(leaf.to_dict()), self._encoded(record)),
            )
            if len(builder.leaves) >= self.epoch_max_leaves:
                checkpoint = self._close_locked(builder, current)
                return EvidencePipelineAppend(leaf, checkpoint.checkpoint_hash)
            return EvidencePipelineAppend(leaf)

    def close_due(self, *, now_us: int | None = None) -> SignedCheckpointV2 | None:
        """Close the active epoch when its configured schedule has elapsed."""
        current = self._clock_us() if now_us is None else now_us
        with self._lock, self._conn:
            state = self._state()
            builder = self._builder(int(state["next_sequence"]))
            if not builder.leaves:
                return None
            if current - int(state["active_started_at_us"]) < self.epoch_max_age_us:
                return None
            return self._close_locked(builder, current)

    def close_active(self, *, now_us: int | None = None) -> SignedCheckpointV2 | None:
        """Force-close pending leaves, for controlled shutdowns and tests."""
        current = self._clock_us() if now_us is None else now_us
        with self._lock, self._conn:
            state = self._state()
            builder = self._builder(int(state["next_sequence"]))
            if not builder.leaves:
                return None
            return self._close_locked(builder, current)

    def _close_locked(
        self, builder: MerkleEpochBuilder, current: int
    ) -> SignedCheckpointV2:
        state = self._state()
        prior_raw = str(state["previous_checkpoint_json"])
        previous = SignedCheckpointV2.from_dict(json.loads(prior_raw)) if prior_raw else None
        checkpoint = builder.sign_checkpoint(
            epoch_id=f"audit-{uuid.uuid4()}",
            issued_at_us=current,
            signer=self.signer,
            previous_checkpoint=previous,
        )
        checkpoint_json = self._encoded(checkpoint.to_dict())
        self._conn.execute(
            """
            INSERT INTO evidence_pipeline_epochs (checkpoint_hash, checkpoint_json, closed_at_us)
            VALUES (?, ?, ?)
            """,
            (checkpoint.checkpoint_hash, checkpoint_json, current),
        )
        for index, leaf in enumerate(builder.leaves):
            envelope = builder.envelope(index, checkpoint)
            self._conn.execute(
                """
                INSERT INTO evidence_pipeline_envelopes (
                    record_id, checkpoint_hash, envelope_json
                ) VALUES (?, ?, ?)
                """,
                (
                    leaf.record_id,
                    checkpoint.checkpoint_hash,
                    self._encoded(envelope.to_dict()),
                ),
            )
        next_sequence = builder.leaves[-1].sequence + 1
        self._conn.execute("DELETE FROM evidence_pipeline_active_entries")
        self._conn.execute(
            """
            UPDATE evidence_pipeline_state
            SET active_started_at_us = ?, next_sequence = ?, previous_checkpoint_json = ?
            WHERE singleton = 1
            """,
            (current, next_sequence, checkpoint_json),
        )
        # The durable outbox isolates provider availability from audit append.
        self.outbox.enqueue(checkpoint, now_us=current)
        return checkpoint

    def get_envelope(self, record_id: str) -> EvidenceEnvelopeV2 | None:
        """Return a closed-record envelope, including any completed anchors."""
        with self._lock:
            row = self._conn.execute(
                "SELECT checkpoint_hash, envelope_json FROM evidence_pipeline_envelopes "
                "WHERE record_id = ?",
                (record_id,),
            ).fetchone()
        if row is None:
            return None
        envelope = EvidenceEnvelopeV2.from_dict(json.loads(row["envelope_json"]))
        job = self.outbox.get(row["checkpoint_hash"])
        return attach_anchors(envelope, job.anchors) if job is not None else envelope

    def run_maintenance(
        self,
        *,
        provider: SigstoreAnchorProvider | None = None,
        max_anchor_jobs: int = 1,
        now_us: int | None = None,
    ) -> tuple[SignedCheckpointV2 | None, int]:
        """One scheduler tick: close an aged epoch and process due anchor jobs."""
        current = self._clock_us() if now_us is None else now_us
        checkpoint = self.close_due(now_us=current)
        processed = 0
        if provider is not None:
            for _ in range(max_anchor_jobs):
                if self.outbox.process_one(provider, now_us=current) is None:
                    break
                processed += 1
        return checkpoint, processed


class V2AuditBackend:
    """Audit backend decorator that emits a V2 leaf for every successful append."""

    def __init__(self, backend: Any, pipeline: AuditEvidencePipeline) -> None:
        if (
            pipeline.source_assurance == AssuranceLevel.HMAC_AUTHENTICATED
            and not self._has_hmac_key(backend)
        ):
            raise ValueError(
                "hmac_authenticated V2 leaves require a keyed audit backend"
            )
        self.backend = backend
        self.pipeline = pipeline

    @staticmethod
    def _has_hmac_key(backend: Any) -> bool:
        """Recognize Pramagent's built-in keyed audit backends conservatively."""
        if getattr(backend, "_signing_key", ""):
            return True
        nested = getattr(backend, "_chain", None)
        return bool(getattr(nested, "_signing_key", ""))

    @property
    def head(self) -> str:
        return self.backend.head

    @property
    def last_prev_hash(self) -> str:
        return self.backend.last_prev_hash

    def append(
        self, payload: dict[str, Any], prev_hash: str | None = None
    ) -> AuditAppendResult:
        result = self.backend.append(payload, prev_hash)
        self.pipeline.record_audit_append(payload, result)
        return result

    def verify_chain(self) -> bool:
        return self.backend.verify_chain()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.backend, name)


__all__ = ["AuditEvidencePipeline", "EvidencePipelineAppend", "V2AuditBackend"]
