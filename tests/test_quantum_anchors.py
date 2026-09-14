from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("pqcrypto")
pytest.importorskip("rfc8785")

from pramagent.quantum import (
    AssuranceLevel,
    EvidenceV2Error,
    ExternalAnchorV2,
    HybridCheckpointSigner,
    MerkleEpochBuilder,
    SQLiteAnchorOutbox,
    SigstoreAnchorProvider,
    attach_anchors,
)


def _epoch():
    signer = HybridCheckpointSigner.generate(
        ed25519_key_id="anchor-ed-test",
        ml_dsa_65_key_id="anchor-pq-test",
    )
    builder = MerkleEpochBuilder()
    now_us = time.time_ns() // 1_000
    builder.append_native(
        record_id="anchor-record",
        observed_at_us=now_us,
        record={
            "record_version": "2.0",
            "event": "anchor_test",
            "recorded_at_us": now_us,
        },
        nonce=b"anchor-test-nonc",
    )
    checkpoint = builder.sign_checkpoint(
        epoch_id="anchor-test-epoch",
        issued_at_us=now_us,
        signer=signer,
    )
    return signer, builder, checkpoint


def _anchor(checkpoint_hash: str, anchor_type: str) -> ExternalAnchorV2:
    return ExternalAnchorV2(
        anchor_type=anchor_type,
        witness_id=f"https://{anchor_type}.example.test",
        checkpoint_hash=checkpoint_hash,
        issued_at_us=time.time_ns() // 1_000,
        artifact_b64=base64.b64encode(b"artifact").decode(),
        anchor_id=f"{anchor_type}-id",
    )


def test_attach_anchors_replaces_type_and_rejects_another_checkpoint():
    _, builder, checkpoint = _epoch()
    envelope = builder.envelope(0, checkpoint)
    first = _anchor(checkpoint.checkpoint_hash, "RFC3161")
    replacement = replace(first, anchor_id="replacement")

    attached = attach_anchors(envelope, [first, replacement])

    assert len(attached.anchors) == 1
    assert attached.anchors[0].anchor_id == "replacement"
    with pytest.raises(EvidenceV2Error, match="another checkpoint"):
        attach_anchors(
            envelope,
            [replace(first, checkpoint_hash="1" * 64)],
        )


def test_rekor_body_binding_rejects_digest_signature_and_certificate_drift():
    digest = b"d" * 32
    signature = b"signature"
    certificate = b"certificate"

    def body(digest_hex=digest.hex(), sig=signature, cert=certificate):
        return json.dumps(
            {
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": {
                    "data": {
                        "hash": {"algorithm": "sha256", "value": digest_hex}
                    },
                    "signature": {
                        "content": base64.b64encode(sig).decode(),
                        "publicKey": {
                            "content": base64.b64encode(cert).decode()
                        },
                    },
                },
            }
        ).encode()

    matches = SigstoreAnchorProvider._rekor_body_matches

    assert matches(
        body(), digest=digest, signature=signature, certificate_pem=certificate
    )
    assert not matches(
        body(digest_hex="0" * 64),
        digest=digest,
        signature=signature,
        certificate_pem=certificate,
    )
    assert not matches(
        body(sig=b"other"),
        digest=digest,
        signature=signature,
        certificate_pem=certificate,
    )
    assert not matches(
        body(cert=b"other"),
        digest=digest,
        signature=signature,
        certificate_pem=certificate,
    )


def test_outbox_retains_tsa_when_publication_retries(tmp_path):
    _, _, checkpoint = _epoch()

    class FlakyProvider:
        def __init__(self):
            self.tsa_calls = 0
            self.log_calls = 0

        def issue_rfc3161(self, signed):
            self.tsa_calls += 1
            return _anchor(signed.checkpoint_hash, "RFC3161")

        def publish_transparency(self, signed):
            self.log_calls += 1
            if self.log_calls == 1:
                raise RuntimeError("temporary log outage")
            return _anchor(signed.checkpoint_hash, "transparency-log")

    provider = FlakyProvider()
    with SQLiteAnchorOutbox(tmp_path / "anchor.sqlite3") as outbox:
        outbox.enqueue(checkpoint, now_us=100)
        first = outbox.process_one(provider, now_us=100)

        assert first is not None
        assert first.status == "retry"
        assert [item.anchor_type for item in first.anchors] == ["RFC3161"]
        assert "temporary log outage" in first.last_error

        second = outbox.process_one(
            provider, now_us=first.next_attempt_at_us
        )

        assert second is not None
        assert second.status == "complete"
        assert {item.anchor_type for item in second.anchors} == {
            "RFC3161",
            "transparency-log",
        }
        assert provider.tsa_calls == 1
        assert provider.log_calls == 2


def test_outbox_enqueue_is_idempotent(tmp_path):
    _, _, checkpoint = _epoch()
    with SQLiteAnchorOutbox(tmp_path / "anchor.sqlite3") as outbox:
        outbox.enqueue(checkpoint, now_us=100)
        outbox.enqueue(checkpoint, now_us=200)

        job = outbox.get(checkpoint.checkpoint_hash)

    assert job is not None
    assert job.status == "queued"
    assert job.attempts == 0


def test_outbox_recovers_an_expired_worker_lease(tmp_path):
    _, _, checkpoint = _epoch()
    with SQLiteAnchorOutbox(tmp_path / "anchor.sqlite3") as outbox:
        outbox.enqueue(checkpoint, now_us=100)
        assert outbox._claim(100, lease_seconds=10) is not None
        assert outbox._claim(101, lease_seconds=10) is None
        assert outbox._claim(10_000_101, lease_seconds=10) is not None


def test_anchor_cli_writes_completed_envelope(tmp_path, monkeypatch, capsys):
    from pramagent import cli

    _, builder, checkpoint = _epoch()
    envelope = builder.envelope(0, checkpoint)
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "anchored.json"
    input_path.write_text(json.dumps(envelope.to_dict()), encoding="utf-8")

    class Provider:
        @classmethod
        def production(cls, **_kwargs):
            return cls()

        def issue_rfc3161(self, signed):
            return _anchor(signed.checkpoint_hash, "RFC3161")

        def publish_transparency(self, signed):
            return _anchor(signed.checkpoint_hash, "transparency-log")

    monkeypatch.setattr("pramagent.quantum.SigstoreAnchorProvider", Provider)
    args = SimpleNamespace(
        envelope=str(input_path),
        output=str(output_path),
        outbox=str(tmp_path / "outbox.sqlite3"),
        trust_cache_only=False,
        timeout=15,
        max_jobs=10,
        json=True,
    )

    assert cli.cmd_evidence_v2_anchor(args) == 0
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert {item["anchor_type"] for item in saved["anchors"]} == {
        "RFC3161",
        "transparency-log",
    }
    assert json.loads(capsys.readouterr().out)["checkpoint_hash"] == (
        checkpoint.checkpoint_hash
    )


@pytest.mark.skipif(
    os.environ.get("PRAMAGENT_RUN_LIVE_SIGSTORE") != "1",
    reason="set PRAMAGENT_RUN_LIVE_SIGSTORE=1 for public-service integration",
)
def test_live_sigstore_tsa_and_rekor_reach_tsa_anchored():
    signer, builder, checkpoint = _epoch()
    provider = SigstoreAnchorProvider.production()
    anchors = provider.issue_all(checkpoint)
    envelope = attach_anchors(builder.envelope(0, checkpoint), anchors)
    trusted_keys = {
        (key.algorithm, key.key_id): key.public_key
        for key in signer.public_keys()
    }

    report = envelope.verify(
        trusted_keys=trusted_keys,
        anchor_verifiers=provider.verifiers(),
        required_assurance=AssuranceLevel.TSA_ANCHORED,
    )

    assert report.valid, report.errors
    assert report.tsa_valid
    assert report.publication_valid
    assert report.assurance_level == AssuranceLevel.TSA_ANCHORED.value

    tsa, publication = anchors
    assert not provider.verify_rfc3161(
        replace(tsa, checkpoint_hash="1" * 64)
    )
    assert not provider.verify_rfc3161(
        replace(tsa, witness_id="https://attacker.invalid")
    )
    assert not provider.verify_transparency(
        replace(publication, anchor_id="wrong:1")
    )
    assert not provider.verify_transparency(
        replace(publication, checkpoint_hash="2" * 64)
    )
