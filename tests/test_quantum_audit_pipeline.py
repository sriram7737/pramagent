from __future__ import annotations

import base64
import asyncio
import pytest

pytest.importorskip("cryptography")
pytest.importorskip("pqcrypto")
pytest.importorskip("rfc8785")

from pramagent import Pramagent
from pramagent.audit import HashChainBackend
from pramagent.quantum import (
    AssuranceLevel,
    AuditEvidencePipeline,
    ExternalAnchorV2,
    HybridCheckpointSigner,
    SQLiteAnchorOutbox,
    V2AuditBackend,
)


def _signer() -> HybridCheckpointSigner:
    return HybridCheckpointSigner.generate(
        ed25519_key_id="audit-ed-test",
        ml_dsa_65_key_id="audit-pq-test",
    )


def _trusted_keys(signer: HybridCheckpointSigner) -> dict[tuple[str, str], bytes]:
    return {
        (key.algorithm, key.key_id): key.public_key for key in signer.public_keys()
    }


class _Provider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    @staticmethod
    def _anchor(checkpoint, anchor_type: str) -> ExternalAnchorV2:
        return ExternalAnchorV2(
            anchor_type=anchor_type,
            witness_id=f"https://{anchor_type}.example.test",
            checkpoint_hash=checkpoint.checkpoint_hash,
            issued_at_us=checkpoint.checkpoint.issued_at_us + 1,
            artifact_b64=base64.b64encode(b"test anchor").decode("ascii"),
            anchor_id=f"{anchor_type}-test",
        )

    def issue_rfc3161(self, checkpoint):
        self.calls.append("RFC3161")
        return self._anchor(checkpoint, "RFC3161")

    def publish_transparency(self, checkpoint):
        self.calls.append("transparency-log")
        return self._anchor(checkpoint, "transparency-log")


def test_wrapped_audit_appends_v2_leaves_closes_epoch_and_anchors_off_path(tmp_path):
    signer = _signer()
    provider = _Provider()
    with SQLiteAnchorOutbox(tmp_path / "outbox.sqlite3") as outbox, AuditEvidencePipeline(
        tmp_path / "pipeline.sqlite3",
        signer=signer,
        outbox=outbox,
        epoch_max_leaves=2,
        source_assurance=AssuranceLevel.HMAC_AUTHENTICATED,
    ) as pipeline:
        backend = V2AuditBackend(HashChainBackend(signing_key="audit-key"), pipeline)
        first = backend.append(
            {"source": "tool_guard", "tenant_id": "acme", "session_id": "s1", "latency_ms": 1.25}
        )
        assert pipeline.get_envelope(first.this_hash) is None
        assert provider.calls == []

        second = backend.append(
            {"source": "tool_guard", "tenant_id": "acme", "session_id": "s1", "latency_ms": 2.5}
        )
        assert backend.verify_chain()
        envelope = pipeline.get_envelope(first.this_hash)
        assert envelope is not None
        assert envelope.leaf.source_assurance == "hmac_authenticated"
        job = outbox.get(envelope.checkpoint.checkpoint_hash)
        assert job.status == "queued"
        assert provider.calls == []

        checkpoint, processed = pipeline.run_maintenance(
            provider=provider, now_us=job.next_attempt_at_us
        )
        assert checkpoint is None
        assert processed == 1
        assert provider.calls == ["RFC3161", "transparency-log"]

        anchored = pipeline.get_envelope(second.this_hash)
        assert anchored is not None
        report = anchored.verify(
            trusted_keys=_trusted_keys(signer),
            anchor_verifiers={"RFC3161": lambda _: True, "transparency-log": lambda _: True},
        )
        assert report.valid
        assert report.record_assurance == "hmac_authenticated"
        assert report.checkpoint_assurance == "tsa_anchored"
        assert {item.anchor_type for item in anchored.anchors} == {
            "RFC3161",
            "transparency-log",
        }


def test_scheduled_close_survives_restart_and_preserves_sequence(tmp_path):
    signer = _signer()
    current = [1_000_000]
    with SQLiteAnchorOutbox(tmp_path / "outbox.sqlite3") as outbox:
        with AuditEvidencePipeline(
            tmp_path / "pipeline.sqlite3",
            signer=signer,
            outbox=outbox,
            epoch_max_leaves=10,
            epoch_max_age_s=10,
            clock_us=lambda: current[0],
        ) as pipeline:
            backend = V2AuditBackend(HashChainBackend(), pipeline)
            result = backend.append({"source": "trace", "tenant_id": "acme"})
            assert pipeline.close_due(now_us=10_999_999) is None

        with AuditEvidencePipeline(
            tmp_path / "pipeline.sqlite3",
            signer=signer,
            outbox=outbox,
            epoch_max_leaves=10,
            epoch_max_age_s=10,
            clock_us=lambda: current[0],
        ) as restored:
            checkpoint = restored.close_due(now_us=11_000_000)
            assert checkpoint is not None
            envelope = restored.get_envelope(result.this_hash)
            assert envelope is not None
            assert envelope.leaf.sequence == 0
            assert checkpoint.checkpoint.first_sequence == 0
            assert checkpoint.checkpoint.last_sequence == 0


def test_hmac_source_assurance_rejects_an_unkeyed_audit_backend(tmp_path):
    signer = _signer()
    with SQLiteAnchorOutbox(tmp_path / "outbox.sqlite3") as outbox, AuditEvidencePipeline(
        tmp_path / "pipeline.sqlite3",
        signer=signer,
        outbox=outbox,
        source_assurance=AssuranceLevel.HMAC_AUTHENTICATED,
    ) as pipeline:
        with pytest.raises(ValueError, match="keyed audit backend"):
            V2AuditBackend(HashChainBackend(), pipeline)


def test_pramagent_option_routes_normal_audit_appends_into_v2_pipeline(tmp_path):
    signer = _signer()
    with SQLiteAnchorOutbox(tmp_path / "outbox.sqlite3") as outbox, AuditEvidencePipeline(
        tmp_path / "pipeline.sqlite3",
        signer=signer,
        outbox=outbox,
        epoch_max_leaves=1,
    ) as pipeline:
        armor = Pramagent(
            audit=HashChainBackend(),
            evidence_pipeline=pipeline,
        )
        armor.validate_tool("unregistered", {"extra": 1})
        response = asyncio.run(armor.run("a normal guarded request"))
        assert response.blocked is False
        records = armor.audit.records()
        assert len(records) == 2
        decision_envelope = pipeline.get_envelope(records[0]["this_hash"])
        trace_envelope = pipeline.get_envelope(records[1]["this_hash"])
        assert decision_envelope is not None
        assert trace_envelope is not None
        assert decision_envelope.record["event_kind"] == "tool_call"
        assert trace_envelope.record["event_kind"] == "trace"
