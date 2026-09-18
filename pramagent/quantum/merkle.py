"""Merkle epochs for portable V2 evidence envelopes."""
from __future__ import annotations

import base64
import hashlib
from typing import Sequence

from .evidence_v2 import (
    AssuranceLevel,
    DEFAULT_SIGNATURE_POLICY,
    GENESIS_CHECKPOINT_HASH,
    CheckpointV2,
    EvidenceEnvelopeV2,
    EvidenceLeafV2,
    EvidenceV2Error,
    ExternalAnchorV2,
    HybridCheckpointSigner,
    SignaturePolicy,
    SignedCheckpointV2,
)


def _hash_leaf_bytes(value: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + value).digest()


def _hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _decode_hash(value: str, label: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise EvidenceV2Error(f"{label} is not hexadecimal") from exc
    if len(raw) != 32 or value != value.lower():
        raise EvidenceV2Error(f"{label} must be lowercase SHA-256")
    return raw


def _largest_power_of_two_less_than(value: int) -> int:
    if value < 2:
        raise EvidenceV2Error("tree split requires at least two leaves")
    return 1 << ((value - 1).bit_length() - 1)


def _root(raw_hashes: Sequence[bytes]) -> bytes:
    size = len(raw_hashes)
    if size == 0:
        return hashlib.sha256(b"").digest()
    if size == 1:
        return raw_hashes[0]
    split = _largest_power_of_two_less_than(size)
    return _hash_children(_root(raw_hashes[:split]), _root(raw_hashes[split:]))


def merkle_root(leaf_hashes: Sequence[str]) -> str:
    return _root([_decode_hash(item, "leaf hash") for item in leaf_hashes]).hex()


def inclusion_proof(leaf_hashes: Sequence[str], index: int) -> tuple[str, ...]:
    raw_hashes = [_decode_hash(item, "leaf hash") for item in leaf_hashes]
    if not raw_hashes or index < 0 or index >= len(raw_hashes):
        raise EvidenceV2Error("inclusion index is outside the tree")

    def build(items: Sequence[bytes], position: int) -> list[bytes]:
        if len(items) == 1:
            return []
        split = _largest_power_of_two_less_than(len(items))
        if position < split:
            return build(items[:split], position) + [_root(items[split:])]
        return build(items[split:], position - split) + [_root(items[:split])]

    return tuple(item.hex() for item in build(raw_hashes, index))


def verify_inclusion_proof(
    leaf_hash: str,
    index: int,
    tree_size: int,
    proof: Sequence[str],
    expected_root: str,
) -> bool:
    if tree_size < 1 or index < 0 or index >= tree_size:
        raise EvidenceV2Error("inclusion proof position is outside the tree")
    current_leaf = _decode_hash(leaf_hash, "leaf hash")
    siblings = [_decode_hash(item, "inclusion proof hash") for item in proof]
    cursor = 0

    def rebuild(position: int, size: int) -> bytes:
        nonlocal cursor
        if size == 1:
            return current_leaf
        split = _largest_power_of_two_less_than(size)
        if position < split:
            left = rebuild(position, split)
            if cursor >= len(siblings):
                raise EvidenceV2Error("inclusion proof is truncated")
            right = siblings[cursor]
            cursor += 1
        else:
            right = rebuild(position - split, size - split)
            if cursor >= len(siblings):
                raise EvidenceV2Error("inclusion proof is truncated")
            left = siblings[cursor]
            cursor += 1
        return _hash_children(left, right)

    calculated = rebuild(index, tree_size)
    if cursor != len(siblings):
        raise EvidenceV2Error("inclusion proof has trailing hashes")
    return calculated == _decode_hash(expected_root, "expected root")


def consistency_proof(
    leaf_hashes: Sequence[str], old_size: int
) -> tuple[str, ...]:
    raw_hashes = [_decode_hash(item, "leaf hash") for item in leaf_hashes]
    new_size = len(raw_hashes)
    if old_size < 1 or old_size > new_size:
        raise EvidenceV2Error("consistency proof size is invalid")
    if old_size == new_size:
        return ()

    def subproof(items: Sequence[bytes], size: int, complete: bool) -> list[bytes]:
        if size == len(items):
            return [] if complete else [_root(items)]
        split = _largest_power_of_two_less_than(len(items))
        if size <= split:
            return subproof(items[:split], size, complete) + [_root(items[split:])]
        return subproof(items[split:], size - split, False) + [_root(items[:split])]

    return tuple(item.hex() for item in subproof(raw_hashes, old_size, True))


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root: str,
    new_root: str,
    proof: Sequence[str],
) -> bool:
    if old_size < 1 or old_size > new_size:
        raise EvidenceV2Error("consistency proof sizes are invalid")
    old_root_bytes = _decode_hash(old_root, "old root")
    new_root_bytes = _decode_hash(new_root, "new root")
    nodes = [_decode_hash(item, "consistency proof hash") for item in proof]
    if old_size == new_size:
        return not nodes and old_root_bytes == new_root_bytes

    old_index = old_size - 1
    new_index = new_size - 1
    while old_index & 1:
        old_index >>= 1
        new_index >>= 1

    cursor = 0
    if old_index == 0:
        old_hash = old_root_bytes
        new_hash = old_root_bytes
    else:
        if not nodes:
            raise EvidenceV2Error("consistency proof is truncated")
        old_hash = nodes[0]
        new_hash = nodes[0]
        cursor = 1

    while cursor < len(nodes):
        if new_index == 0:
            raise EvidenceV2Error("consistency proof has trailing hashes")
        node = nodes[cursor]
        if (old_index & 1) or old_index == new_index:
            old_hash = _hash_children(node, old_hash)
            new_hash = _hash_children(node, new_hash)
            while old_index and not (old_index & 1):
                old_index >>= 1
                new_index >>= 1
        else:
            new_hash = _hash_children(new_hash, node)
        old_index >>= 1
        new_index >>= 1
        cursor += 1

    return old_hash == old_root_bytes and new_hash == new_root_bytes


class MerkleEpochBuilder:
    """Build one append-only epoch and retain leaf nonces with each record."""

    def __init__(self, *, start_sequence: int = 0) -> None:
        if type(start_sequence) is not int or start_sequence < 0:
            raise EvidenceV2Error("start_sequence must be a non-negative integer")
        self._start_sequence = start_sequence
        self._leaves: list[EvidenceLeafV2] = []
        self._records: list[dict | None] = []

    @property
    def leaves(self) -> tuple[EvidenceLeafV2, ...]:
        return tuple(self._leaves)

    def to_dict(self) -> dict:
        """Return a durable snapshot containing every record and leaf nonce."""
        return {
            "entries": [
                {"leaf": leaf.to_dict(), "record": record}
                for leaf, record in zip(self._leaves, self._records)
            ],
            "snapshot_version": "1",
            "start_sequence": self._start_sequence,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "MerkleEpochBuilder":
        if set(raw) != {"entries", "snapshot_version", "start_sequence"}:
            raise EvidenceV2Error("Merkle snapshot fields do not match schema")
        if raw["snapshot_version"] != "1" or not isinstance(raw["entries"], list):
            raise EvidenceV2Error("unsupported Merkle snapshot")
        builder = cls(start_sequence=raw["start_sequence"])
        expected_sequence = builder._start_sequence
        for entry in raw["entries"]:
            if not isinstance(entry, dict) or set(entry) != {"leaf", "record"}:
                raise EvidenceV2Error("Merkle snapshot entry fields do not match schema")
            leaf = EvidenceLeafV2.from_dict(entry["leaf"])
            record = entry["record"]
            if leaf.sequence != expected_sequence:
                raise EvidenceV2Error("Merkle snapshot sequence is not contiguous")
            if leaf.provenance_mode == "native-v2":
                if not isinstance(record, dict):
                    raise EvidenceV2Error("native Merkle leaf is missing its record")
                expected = EvidenceLeafV2.create_native(
                    record_id=leaf.record_id,
                    sequence=leaf.sequence,
                    observed_at_us=leaf.observed_at_us,
                    record=record,
                    nonce=base64.b64decode(leaf.nonce_b64, validate=True),
                    source_assurance=AssuranceLevel(leaf.source_assurance),
                )
                if expected != leaf:
                    raise EvidenceV2Error("Merkle snapshot record does not match its leaf")
            elif record is not None:
                raise EvidenceV2Error("legacy Merkle snapshot must not embed V1 record bytes")
            builder._leaves.append(leaf)
            builder._records.append(record)
            expected_sequence += 1
        return builder

    def append_native(
        self,
        *,
        record_id: str,
        observed_at_us: int,
        record: dict,
        nonce: bytes | None = None,
        source_assurance: AssuranceLevel = AssuranceLevel.CHECKSUM_ONLY,
    ) -> EvidenceLeafV2:
        sequence = (
            self._leaves[-1].sequence + 1
            if self._leaves
            else self._start_sequence
        )
        leaf = EvidenceLeafV2.create_native(
            record_id=record_id,
            sequence=sequence,
            observed_at_us=observed_at_us,
            record=record,
            nonce=nonce,
            source_assurance=source_assurance,
        )
        self._leaves.append(leaf)
        self._records.append(record)
        return leaf

    def append_legacy_v1(
        self,
        *,
        record_id: str,
        observed_at_us: int,
        record_digest: str,
        nonce: bytes | None = None,
    ) -> EvidenceLeafV2:
        sequence = (
            self._leaves[-1].sequence + 1
            if self._leaves
            else self._start_sequence
        )
        leaf = EvidenceLeafV2.wrap_legacy_v1(
            record_id=record_id,
            sequence=sequence,
            observed_at_us=observed_at_us,
            record_digest=record_digest,
            nonce=nonce,
        )
        self._leaves.append(leaf)
        self._records.append(None)
        return leaf

    def root(self, *, size: int | None = None) -> str:
        selected = self._leaves if size is None else self._leaves[:size]
        if not selected:
            raise EvidenceV2Error("cannot checkpoint an empty epoch")
        return merkle_root([item.leaf_hash for item in selected])

    def sign_checkpoint(
        self,
        *,
        epoch_id: str,
        issued_at_us: int,
        signer: HybridCheckpointSigner,
        previous_checkpoint: SignedCheckpointV2 | None = None,
        policy: SignaturePolicy = DEFAULT_SIGNATURE_POLICY,
    ) -> SignedCheckpointV2:
        if not self._leaves:
            raise EvidenceV2Error("cannot checkpoint an empty epoch")
        checkpoint = CheckpointV2(
            epoch_id=epoch_id,
            tree_size=len(self._leaves),
            first_sequence=self._leaves[0].sequence,
            last_sequence=self._leaves[-1].sequence,
            merkle_root=self.root(),
            issued_at_us=issued_at_us,
            previous_checkpoint_hash=(
                previous_checkpoint.checkpoint_hash
                if previous_checkpoint is not None
                else GENESIS_CHECKPOINT_HASH
            ),
            signature_policy_version=policy.policy_version,
            required_signature_algorithms=policy.required_algorithms,
        )
        return signer.sign(checkpoint, policy=policy)

    def envelope(
        self,
        index: int,
        checkpoint: SignedCheckpointV2,
        *,
        anchors: Sequence[ExternalAnchorV2] = (),
    ) -> EvidenceEnvelopeV2:
        if index < 0 or index >= len(self._leaves):
            raise EvidenceV2Error("envelope index is outside the epoch")
        if checkpoint.checkpoint.tree_size != len(self._leaves):
            raise EvidenceV2Error("checkpoint does not cover the current epoch")
        hashes = [item.leaf_hash for item in self._leaves]
        return EvidenceEnvelopeV2(
            leaf=self._leaves[index],
            checkpoint=checkpoint,
            inclusion_proof=inclusion_proof(hashes, index),
            record=self._records[index],
            anchors=tuple(anchors),
        )

    def consistency_proof(self, old_size: int) -> tuple[str, ...]:
        return consistency_proof(
            [item.leaf_hash for item in self._leaves], old_size
        )


__all__ = [
    "MerkleEpochBuilder",
    "consistency_proof",
    "inclusion_proof",
    "merkle_root",
    "verify_consistency_proof",
    "verify_inclusion_proof",
]
