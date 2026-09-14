from __future__ import annotations

import base64
import os
import threading
import time
import uuid

import pytest

from pramagent._pg import connect as pg_connect
from pramagent.quantum import (
    ExternalAnchorV2,
    HybridCheckpointSigner,
    MerkleEpochBuilder,
    PostgresAnchorOutbox,
)


def _checkpoint(number: int):
    signer = HybridCheckpointSigner.generate(
        ed25519_key_id=f"live-anchor-ed-{number}",
        ml_dsa_65_key_id=f"live-anchor-pq-{number}",
    )
    builder = MerkleEpochBuilder()
    now_us = time.time_ns() // 1_000 + number
    builder.append_native(
        record_id=f"live-anchor-{number}",
        observed_at_us=now_us,
        record={"record_version": "2.0", "number": number},
        nonce=number.to_bytes(16, "big"),
    )
    return builder.sign_checkpoint(
        epoch_id=f"live-anchor-epoch-{number}",
        issued_at_us=now_us,
        signer=signer,
    )


def _anchor(checkpoint_hash: str, anchor_type: str) -> ExternalAnchorV2:
    return ExternalAnchorV2(
        anchor_type=anchor_type,
        witness_id=f"https://{anchor_type}.example.test",
        checkpoint_hash=checkpoint_hash,
        issued_at_us=time.time_ns() // 1_000,
        artifact_b64=base64.b64encode(b"live-test-artifact").decode(),
        anchor_id=f"{anchor_type}-{checkpoint_hash[:12]}",
    )


@pytest.mark.skipif(
    not os.environ.get("PRAMAGENT_TEST_POSTGRES_DSN"),
    reason="set PRAMAGENT_TEST_POSTGRES_DSN to run the live Postgres test",
)
def test_live_postgres_anchor_workers_claim_distinct_jobs():
    dsn = os.environ["PRAMAGENT_TEST_POSTGRES_DSN"]
    table = f"anchor_outbox_test_{uuid.uuid4().hex[:12]}"
    outboxes = [
        PostgresAnchorOutbox(dsn, table=table),
        PostgresAnchorOutbox(dsn, table=table),
    ]
    checkpoints = [_checkpoint(1), _checkpoint(2)]
    for checkpoint in checkpoints:
        outboxes[0].enqueue(checkpoint, now_us=100)

    barrier = threading.Barrier(2)
    results = []
    errors = []

    class Provider:
        def issue_rfc3161(self, signed):
            return _anchor(signed.checkpoint_hash, "RFC3161")

        def publish_transparency(self, signed):
            return _anchor(signed.checkpoint_hash, "transparency-log")

    def process(outbox):
        try:
            barrier.wait()
            results.append(outbox.process_one(Provider(), now_us=100))
        except Exception as exc:  # pragma: no cover - reported by main thread
            errors.append(exc)

    try:
        threads = [
            threading.Thread(target=process, args=(outbox,))
            for outbox in outboxes
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        assert not any(thread.is_alive() for thread in threads)
        assert errors == []
        assert len(results) == 2
        assert all(result is not None and result.status == "complete" for result in results)
        assert {result.checkpoint_hash for result in results} == {
            checkpoint.checkpoint_hash for checkpoint in checkpoints
        }
    finally:
        connection = pg_connect(dsn)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"DROP TABLE IF EXISTS {table}")
            connection.commit()
        finally:
            connection.close()
