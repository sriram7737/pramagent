from __future__ import annotations

import base64
import hashlib
import json
import os
import time

import pytest

pytest.importorskip("pyasn1")
pytest.importorskip("pyasn1_modules")

from pyasn1.codec.der import encoder
from pyasn1.type import useful
from pyasn1_modules import rfc3161, rfc5280, rfc5652

from pramagent.quantum import (
    ExternalAnchorV2,
    HybridCheckpointSigner,
    MerkleEpochBuilder,
    RFC4998Error,
    RFC4998ArchiveBundle,
    append_timestamp_renewal,
    checkpoint_archived_object,
    create_archive_bundle,
    create_evidence_record,
    renew_archive_bundle,
    timestamp_renewal_payload,
    verify_evidence_record,
    verify_archive_bundle,
)
from pramagent.quantum.anchors import RFC3161_ARTIFACT_VERSION


SHA256_OID = "2.16.840.1.101.3.4.2.1"


def _algorithm():
    value = rfc5280.AlgorithmIdentifier()
    value["algorithm"] = SHA256_OID
    value["parameters"] = b"\x05\x00"
    return value


def _timestamp_response(payload: bytes, serial: int) -> bytes:
    info = rfc3161.TSTInfo()
    info["version"] = 1
    info["policy"] = "1.3.6.1.4.1.57264.3.1"
    info["messageImprint"]["hashAlgorithm"] = _algorithm()
    info["messageImprint"]["hashedMessage"] = hashlib.sha256(payload).digest()
    info["serialNumber"] = serial
    info["genTime"] = useful.GeneralizedTime("20260913235959Z")

    signed = rfc5652.SignedData()
    signed["version"] = 3
    signed["digestAlgorithms"].append(_algorithm())
    signed["encapContentInfo"]["eContentType"] = rfc3161.id_ct_TSTInfo
    signed["encapContentInfo"]["eContent"] = encoder.encode(info)

    response = rfc3161.TimeStampResp()
    response["status"]["status"] = 0
    response["timeStampToken"]["contentType"] = rfc5652.id_signedData
    response["timeStampToken"]["content"] = encoder.encode(signed)
    return encoder.encode(response)


def _anchor(
    payload: bytes, serial: int = 1, *, reference_hash: str | None = None
) -> ExternalAnchorV2:
    response = _timestamp_response(payload, serial)
    artifact = {
        "artifact_version": RFC3161_ARTIFACT_VERSION,
        "nonce_decimal": str(serial),
        "request_b64": base64.b64encode(b"request").decode(),
        "response_b64": base64.b64encode(response).decode(),
    }
    return ExternalAnchorV2(
        anchor_type="RFC3161",
        witness_id="https://tsa.example.test",
        checkpoint_hash=reference_hash or hashlib.sha256(payload).hexdigest(),
        issued_at_us=1_789_343_999_000_000 + serial,
        artifact_b64=base64.b64encode(
            json.dumps(artifact, separators=(",", ":")).encode()
        ).decode(),
        anchor_id=hashlib.sha256(response).hexdigest(),
    )


def test_rfc4998_initial_record_roundtrips_and_binds_object():
    archived = b"signed checkpoint material"
    record = create_evidence_record(
        archived, _anchor(archived), anchor_verifier=lambda _anchor: True
    )

    report = verify_evidence_record(record, archived)
    drifted = verify_evidence_record(record, archived + b"!")

    assert report.valid
    assert report.timestamp_count == 1
    assert not drifted.valid
    assert "does not bind" in drifted.errors[0]


def test_rfc4998_timestamp_renewal_chains_previous_token():
    archived = b"long-retention checkpoint"
    record = create_evidence_record(
        archived, _anchor(archived), anchor_verifier=lambda _anchor: True
    )
    renewal_payload = timestamp_renewal_payload(record)
    renewed = append_timestamp_renewal(
        record,
        _anchor(renewal_payload, serial=2),
        anchor_verifier=lambda _anchor: True,
    )

    report = verify_evidence_record(renewed, archived)

    assert report.valid
    assert report.timestamp_count == 2
    assert len(renewed) > len(record)


def test_rfc4998_rejects_unverified_and_misbound_timestamps():
    archived = b"checkpoint"
    with pytest.raises(RFC4998Error, match="verification failed"):
        create_evidence_record(
            archived, _anchor(archived), anchor_verifier=lambda _anchor: False
        )
    with pytest.raises(RFC4998Error, match="does not bind"):
        create_evidence_record(
            archived, _anchor(b"another object"), anchor_verifier=lambda _anchor: True
        )


def test_rfc4998_rejects_trailing_der_and_wrong_renewal_payload():
    archived = b"checkpoint"
    record = create_evidence_record(
        archived, _anchor(archived), anchor_verifier=lambda _anchor: True
    )
    with pytest.raises(RFC4998Error, match="trailing"):
        timestamp_renewal_payload(record + b"junk")
    with pytest.raises(RFC4998Error, match="does not bind"):
        append_timestamp_renewal(
            record,
            _anchor(b"wrong renewal"),
            anchor_verifier=lambda _anchor: True,
        )


def test_archive_bundle_retains_and_verifies_timestamp_artifacts():
    checkpoint_hash = "a" * 64
    archived = checkpoint_archived_object(checkpoint_hash)
    initial = _anchor(archived, reference_hash=checkpoint_hash)
    bundle = create_archive_bundle(
        checkpoint_hash,
        initial,
        anchor_verifier=lambda _anchor: True,
        now_us=100,
    )
    payload = timestamp_renewal_payload(
        base64.b64decode(bundle.evidence_record_der_b64)
    )
    renewed = renew_archive_bundle(
        bundle,
        _anchor(payload, serial=2),
        anchor_verifier=lambda _anchor: True,
        now_us=200,
    )
    restored = RFC4998ArchiveBundle.from_json(json.dumps(renewed.to_dict()))

    report = verify_archive_bundle(
        restored,
        initial_anchor_verifier=lambda _anchor: True,
        renewal_anchor_verifier=lambda _anchor, _payload: True,
    )

    assert report.valid, report.errors
    assert report.timestamp_count == 2
    assert report.external_timestamps_valid


def test_archive_bundle_hash_detects_artifact_substitution():
    checkpoint_hash = "b" * 64
    archived = checkpoint_archived_object(checkpoint_hash)
    bundle = create_archive_bundle(
        checkpoint_hash,
        _anchor(archived, reference_hash=checkpoint_hash),
        anchor_verifier=lambda _anchor: True,
        now_us=100,
    )
    raw = bundle.to_dict()
    raw["timestamp_anchors"][0]["anchor_id"] = "substituted"

    with pytest.raises(RFC4998Error, match="hash mismatch"):
        RFC4998ArchiveBundle.from_dict(raw)


@pytest.mark.skipif(
    os.environ.get("PRAMAGENT_RUN_LIVE_SIGSTORE") != "1",
    reason="set PRAMAGENT_RUN_LIVE_SIGSTORE=1 for public-service integration",
)
def test_live_sigstore_creates_and_renews_rfc4998_record():
    from pramagent.quantum import SigstoreAnchorProvider

    signer = HybridCheckpointSigner.generate(
        ed25519_key_id="live-rfc4998-ed",
        ml_dsa_65_key_id="live-rfc4998-pq",
    )
    builder = MerkleEpochBuilder()
    now_us = time.time_ns() // 1_000
    builder.append_native(
        record_id="live-rfc4998-record",
        observed_at_us=now_us,
        record={"record_version": "2.0", "event": "rfc4998_live_test"},
        nonce=b"live-rfc4998-tst",
    )
    checkpoint = builder.sign_checkpoint(
        epoch_id="live-rfc4998-epoch",
        issued_at_us=now_us,
        signer=signer,
    )
    provider = SigstoreAnchorProvider.production()
    initial_anchor = provider.issue_rfc3161(checkpoint)
    revocation = [
        json.loads(base64.b64decode(item))
        for item in initial_anchor.revocation_material_b64
    ]
    assert revocation
    assert {item["status"] for item in revocation} == {
        "no_endpoint_advertised"
    }
    archived = checkpoint_archived_object(checkpoint.checkpoint_hash)
    record = create_evidence_record(
        archived,
        initial_anchor,
        anchor_verifier=provider.verify_rfc3161,
    )
    renewal_payload = timestamp_renewal_payload(record)
    renewal_anchor = provider.issue_archive_timestamp(renewal_payload)
    renewed = append_timestamp_renewal(
        record,
        renewal_anchor,
        anchor_verifier=lambda anchor: provider.verify_archive_timestamp(
            anchor, renewal_payload
        ),
    )

    report = verify_evidence_record(renewed, archived)

    assert report.valid, report.errors
    assert report.timestamp_count == 2
