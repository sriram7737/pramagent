from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("pqcrypto")
pytest.importorskip("rfc8785")

from pramagent.quantum import (
    AssuranceLevel,
    CheckpointV2,
    DEFAULT_SIGNATURE_POLICY,
    EvidenceEnvelopeV2,
    EvidenceLeafV2,
    EvidenceV2Error,
    ExternalAnchorV2,
    HybridCheckpointSigner,
    MerkleEpochBuilder,
    SignatureEntry,
    SignaturePolicy,
    SignedCheckpointV2,
    VerificationKey,
    canonicalize_jcs,
    merkle_root,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_signed_checkpoint,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "pramagent"
    / "quantum"
    / "data"
    / "evidence_envelope_v2_golden.json"
)


def _record(number: int) -> dict:
    return {
        "record_version": "2.0",
        "event": "tool_decision",
        "recorded_at_us": 1_789_330_013_732_744 + number,
        "cost_microusd": number * 125,
        "sequence": number,
        "tenant_ref": f"tenant-{number}",
    }


@pytest.fixture(scope="module")
def signer():
    return HybridCheckpointSigner.generate(
        ed25519_key_id="ed-test-1", ml_dsa_65_key_id="pq-test-1"
    )


def _trusted_keys(signer: HybridCheckpointSigner) -> dict[tuple[str, str], bytes]:
    return {
        (key.algorithm, key.key_id): key.public_key
        for key in signer.public_keys()
    }


def _signed_epoch(signer: HybridCheckpointSigner, count: int = 4):
    builder = MerkleEpochBuilder()
    for number in range(count):
        builder.append_native(
            record_id=f"record-{number}",
            observed_at_us=1_789_330_013_732_744 + number,
            record=_record(number),
            nonce=bytes([number]) * 16,
        )
    checkpoint = builder.sign_checkpoint(
        epoch_id="epoch-2026-09-13T00",
        issued_at_us=1_789_330_014_000_000,
        signer=signer,
    )
    return builder, checkpoint


def test_jcs_integer_profile_uses_utf8_and_rejects_floats():
    value = {"z": 2, "a": "Euro: \u20ac", "nested": {"x": 1}}

    assert canonicalize_jcs(value) == (
        b'{"a":"Euro: \xe2\x82\xac","nested":{"x":1},"z":2}'
    )
    with pytest.raises(EvidenceV2Error, match="float"):
        canonicalize_jcs({"nested": [{"seconds": 1.25}]})
    with pytest.raises(EvidenceV2Error, match="safe-integer"):
        canonicalize_jcs({"value": 9_007_199_254_740_992})


def test_leaf_nonce_is_persisted_and_part_of_the_hash():
    first = EvidenceLeafV2.create_native(
        record_id="record-1",
        sequence=0,
        observed_at_us=10,
        record=_record(1),
        nonce=b"a" * 16,
    )
    second = EvidenceLeafV2.create_native(
        record_id="record-1",
        sequence=0,
        observed_at_us=10,
        record=_record(1),
        nonce=b"b" * 16,
    )

    assert first.record_digest == second.record_digest
    assert first.leaf_hash != second.leaf_hash
    assert EvidenceLeafV2.from_dict(first.to_dict()) == first


def test_merkle_inclusion_and_consistency_proofs_cover_unbalanced_trees():
    builder = MerkleEpochBuilder()
    roots = {}
    for number in range(9):
        builder.append_native(
            record_id=f"record-{number}",
            observed_at_us=number + 1,
            record=_record(number),
            nonce=bytes([number]) * 16,
        )
        roots[number + 1] = builder.root()

    hashes = [leaf.leaf_hash for leaf in builder.leaves]
    for index, leaf_hash in enumerate(hashes):
        from pramagent.quantum import inclusion_proof

        proof = inclusion_proof(hashes, index)
        assert verify_inclusion_proof(
            leaf_hash, index, len(hashes), proof, roots[len(hashes)]
        )
    for old_size in range(1, len(hashes)):
        proof = builder.consistency_proof(old_size)
        assert verify_consistency_proof(
            old_size, len(hashes), roots[old_size], roots[len(hashes)], proof
        )

    proof = list(builder.consistency_proof(4))
    proof[0] = ("0" if proof[0][0] != "0" else "1") + proof[0][1:]
    assert not verify_consistency_proof(
        4, len(hashes), roots[4], roots[len(hashes)], proof
    )


def test_merkle_snapshot_persists_nonce_and_detects_record_tampering():
    builder = MerkleEpochBuilder(start_sequence=40)
    leaf = builder.append_native(
        record_id="durable-record",
        observed_at_us=100,
        record=_record(1),
        nonce=b"persisted-nonce!",
    )
    snapshot = builder.to_dict()

    restored = MerkleEpochBuilder.from_dict(snapshot)

    assert restored.leaves[0] == leaf
    assert restored.to_dict() == snapshot
    snapshot["entries"][0]["record"]["cost_microusd"] += 1
    with pytest.raises(EvidenceV2Error, match="does not match"):
        MerkleEpochBuilder.from_dict(snapshot)


def test_hybrid_checkpoint_requires_both_signatures(signer):
    _, checkpoint = _signed_epoch(signer)
    trusted = _trusted_keys(signer)

    assert verify_signed_checkpoint(checkpoint, trusted_keys=trusted).valid

    stripped = SignedCheckpointV2(
        checkpoint=checkpoint.checkpoint,
        signatures=checkpoint.signatures[:1],
    ).seal()
    result = verify_signed_checkpoint(stripped, trusted_keys=trusted)

    assert not result.valid
    assert result.errors == ("missing required signatures: ML-DSA-65",)


def test_policy_substitution_and_extra_signatures_fail(signer):
    _, checkpoint = _signed_epoch(signer)
    trusted = _trusted_keys(signer)
    weaker = replace(
        checkpoint.checkpoint,
        required_signature_algorithms=("Ed25519",),
    )
    substituted = SignedCheckpointV2(
        checkpoint=weaker,
        signatures=checkpoint.signatures,
    ).seal()
    extra = SignedCheckpointV2(
        checkpoint=checkpoint.checkpoint,
        signatures=checkpoint.signatures
        + (SignatureEntry("future-algorithm", "future-key", base64.b64encode(b"x").decode()),),
    ).seal()

    assert not verify_signed_checkpoint(substituted, trusted_keys=trusted).valid
    assert not verify_signed_checkpoint(extra, trusted_keys=trusted).valid


def test_new_policy_version_allows_rotation_without_downgrade(signer):
    policy = SignaturePolicy(
        "pramagent-hybrid-2027-01",
        DEFAULT_SIGNATURE_POLICY.required_algorithms,
    )
    builder, _ = _signed_epoch(signer)
    checkpoint = builder.sign_checkpoint(
        epoch_id="epoch-rotation",
        issued_at_us=1_800_000_000_000_000,
        signer=signer,
        policy=policy,
    )

    untrusted = verify_signed_checkpoint(
        checkpoint, trusted_keys=_trusted_keys(signer)
    )
    trusted = verify_signed_checkpoint(
        checkpoint,
        trusted_keys=_trusted_keys(signer),
        trusted_policies={policy.policy_version: policy},
    )

    assert not untrusted.valid
    assert trusted.valid


def test_checkpoint_chain_advances_across_epoch_builders(signer):
    first_builder, first_checkpoint = _signed_epoch(signer, count=2)
    second_builder = MerkleEpochBuilder(
        start_sequence=first_checkpoint.checkpoint.last_sequence + 1
    )
    second_builder.append_native(
        record_id="next-epoch-record",
        observed_at_us=1_800_000_000_000_001,
        record=_record(20),
        nonce=b"next-epoch-nonce",
    )
    second_checkpoint = second_builder.sign_checkpoint(
        epoch_id="epoch-next",
        issued_at_us=1_800_000_000_000_002,
        signer=signer,
        previous_checkpoint=first_checkpoint,
    )

    result = verify_signed_checkpoint(
        second_checkpoint,
        trusted_keys=_trusted_keys(signer),
        previous_checkpoint=first_checkpoint,
    )

    assert first_builder.leaves[-1].sequence == 1
    assert second_builder.leaves[0].sequence == 2
    assert result.valid


def test_native_envelope_roundtrips_and_reports_asymmetric_assurance(signer):
    builder, checkpoint = _signed_epoch(signer)
    envelope = builder.envelope(2, checkpoint)
    restored = EvidenceEnvelopeV2.from_dict(envelope.to_dict())

    report = restored.verify(trusted_keys=_trusted_keys(signer))

    assert report.valid
    assert report.assurance_level == "asymmetric_checkpointed"
    assert report.record_assurance == "checksum_only"
    assert report.checkpoint.verified_algorithms == ("Ed25519", "ML-DSA-65")


def test_tsa_assurance_requires_timestamp_and_independent_publication(signer):
    builder, checkpoint = _signed_epoch(signer)
    tsa = ExternalAnchorV2(
        anchor_type="RFC3161",
        witness_id="tsa.example",
        checkpoint_hash=checkpoint.checkpoint_hash,
        issued_at_us=1_789_330_014_100_000,
        artifact_b64=base64.b64encode(b"DER timestamp token").decode(),
        certificate_chain_b64=(base64.b64encode(b"certificate chain").decode(),),
        revocation_material_b64=(base64.b64encode(b"OCSP response").decode(),),
        anchor_id="tsa-serial-1",
    )
    publication = ExternalAnchorV2(
        anchor_type="transparency-log",
        witness_id="log.example",
        checkpoint_hash=checkpoint.checkpoint_hash,
        issued_at_us=1_789_330_014_200_000,
        artifact_b64=base64.b64encode(b"signed log receipt").decode(),
        anchor_id="log-index-1",
    )
    timestamp_only = replace(builder.envelope(0, checkpoint), anchors=(tsa,))
    complete = replace(
        builder.envelope(0, checkpoint), anchors=(tsa, publication)
    )
    verifiers = {"RFC3161": lambda anchor: True, "transparency-log": lambda anchor: True}

    partial = timestamp_only.verify(
        trusted_keys=_trusted_keys(signer), anchor_verifiers=verifiers
    )
    full = complete.verify(
        trusted_keys=_trusted_keys(signer),
        anchor_verifiers=verifiers,
        required_assurance=AssuranceLevel.TSA_ANCHORED,
    )

    assert partial.assurance_level == "asymmetric_checkpointed"
    assert "lacks an independently verified publication" in partial.warnings[0]
    assert full.valid
    assert full.assurance_level == "tsa_anchored"


def test_unverified_anchor_never_raises_assurance(signer):
    builder, checkpoint = _signed_epoch(signer)
    anchor = ExternalAnchorV2(
        anchor_type="RFC3161",
        witness_id="operator-value",
        checkpoint_hash=checkpoint.checkpoint_hash,
        issued_at_us=checkpoint.checkpoint.issued_at_us + 1,
        artifact_b64=base64.b64encode(b"not verified").decode(),
        anchor_id="claimed-only",
    )
    envelope = replace(builder.envelope(0, checkpoint), anchors=(anchor,))

    report = envelope.verify(trusted_keys=_trusted_keys(signer))

    assert report.valid
    assert not report.tsa_valid
    assert report.assurance_level == "asymmetric_checkpointed"
    assert "no verifier configured for RFC3161" in report.warnings


def test_legacy_v1_wrap_never_gains_retroactive_assurance(signer):
    builder = MerkleEpochBuilder()
    builder.append_legacy_v1(
        record_id="legacy-1",
        observed_at_us=100,
        record_digest="a" * 64,
        nonce=b"legacy-nonce-0001",
    )
    checkpoint = builder.sign_checkpoint(
        epoch_id="legacy-epoch", issued_at_us=200, signer=signer
    )
    envelope = builder.envelope(0, checkpoint)

    report = envelope.verify(trusted_keys=_trusted_keys(signer))

    assert report.valid
    assert report.assurance_level == "checksum_only"
    assert report.checkpoint_assurance == "asymmetric_checkpointed"
    assert "not original authorship" in report.warnings[0]


def test_strict_schema_rejects_unknown_fields(signer):
    builder, checkpoint = _signed_epoch(signer)
    payload = builder.envelope(0, checkpoint).to_dict()
    payload["leaf"]["future"] = "silently ignored"

    with pytest.raises(EvidenceV2Error, match="extra=.*future"):
        EvidenceEnvelopeV2.from_dict(payload)


def test_json_reader_rejects_duplicate_properties_before_parsing():
    with pytest.raises(EvidenceV2Error, match="duplicate JSON property 'anchors'"):
        EvidenceEnvelopeV2.from_json('{"anchors":[],"anchors":[]}')


def test_verifier_cli_emits_required_assurance_fields(tmp_path, capsys):
    from pramagent import cli

    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    envelope_path = tmp_path / "envelope.json"
    keys_path = tmp_path / "trusted-keys.json"
    envelope_path.write_text(json.dumps(vector["envelope"]), encoding="utf-8")
    keys_path.write_text(
        json.dumps({"keys": vector["verification_keys"]}), encoding="utf-8"
    )
    args = SimpleNamespace(
        envelope=str(envelope_path),
        keys=str(keys_path),
        require_assurance="asymmetric_checkpointed",
        json=True,
    )

    assert cli.cmd_evidence_v2_verify(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["assurance_level"] == "asymmetric_checkpointed"
    assert output["record_assurance"] == "checksum_only"
    assert output["checkpoint_assurance"] == "asymmetric_checkpointed"


def test_verifier_cli_accepts_golden_vector_bare_key_list(tmp_path, capsys):
    from pramagent import cli

    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    envelope_path = tmp_path / "envelope.json"
    keys_path = tmp_path / "trusted-keys.json"
    envelope_path.write_text(json.dumps(vector["envelope"]), encoding="utf-8")
    keys_path.write_text(json.dumps(vector["verification_keys"]), encoding="utf-8")
    args = SimpleNamespace(
        envelope=str(envelope_path),
        keys=str(keys_path),
        require_assurance="asymmetric_checkpointed",
        json=True,
    )

    assert cli.cmd_evidence_v2_verify(args) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_golden_vector_verifies_cross_language_material():
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    keys = {
        (item["algorithm"], item["key_id"]): VerificationKey.from_dict(item).public_key
        for item in vector["verification_keys"]
    }
    envelope = EvidenceEnvelopeV2.from_dict(vector["envelope"])

    assert canonicalize_jcs(vector["jcs_input"]).hex() == vector["jcs_hex"]
    assert envelope.leaf.leaf_hash == vector["leaf_hash"]
    assert envelope.checkpoint.checkpoint.merkle_root == vector["merkle_root"]
    assert envelope.verify(trusted_keys=keys).valid
    assert verify_consistency_proof(
        vector["consistency"]["old_size"],
        vector["consistency"]["new_size"],
        vector["consistency"]["old_root"],
        vector["consistency"]["new_root"],
        vector["consistency"]["proof"],
    )
