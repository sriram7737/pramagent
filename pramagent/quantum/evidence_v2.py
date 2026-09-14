"""Portable, policy-versioned evidence envelopes.

Version 2 is additive. It does not change the byte representation or validation
rules of the version 1 quantum evidence classes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping


SCHEMA_VERSION = "2.0"
LEAF_DOMAIN = "pramagent:evidence-leaf:v2"
CHECKPOINT_DOMAIN = "pramagent:evidence-checkpoint:v2"
CHECKPOINT_SIGNATURE_PREFIX = b"pramagent:evidence-checkpoint:v2\x00"
MAX_JCS_INTEGER = 9_007_199_254_740_991
GENESIS_CHECKPOINT_HASH = "0" * 64
ED25519 = "Ed25519"
ML_DSA_65 = "ML-DSA-65"


class EvidenceV2Error(ValueError):
    """Raised when a V2 envelope is malformed or internally inconsistent."""


class EvidenceV2DependencyError(RuntimeError):
    """Raised when an optional cryptographic dependency is unavailable."""


class AssuranceLevel(str, Enum):
    CHECKSUM_ONLY = "checksum_only"
    HMAC_AUTHENTICATED = "hmac_authenticated"
    ASYMMETRIC_CHECKPOINTED = "asymmetric_checkpointed"
    TSA_ANCHORED = "tsa_anchored"


_ASSURANCE_RANK = {
    AssuranceLevel.CHECKSUM_ONLY: 0,
    AssuranceLevel.HMAC_AUTHENTICATED: 1,
    AssuranceLevel.ASYMMETRIC_CHECKPOINTED: 2,
    AssuranceLevel.TSA_ANCHORED: 3,
}


def _exact_fields(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceV2Error(
            f"{label} fields do not match schema; missing={missing}, extra={extra}"
        )


def _valid_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _require_safe_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise EvidenceV2Error(f"{label} must be an integer")
    if value < minimum or value > MAX_JCS_INTEGER:
        raise EvidenceV2Error(
            f"{label} must be between {minimum} and {MAX_JCS_INTEGER}"
        )
    return value


def _validate_jcs_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise EvidenceV2Error(f"{path} contains invalid Unicode") from exc
        return
    if type(value) is int:
        if abs(value) > MAX_JCS_INTEGER:
            raise EvidenceV2Error(f"{path} exceeds the JCS safe-integer range")
        return
    if isinstance(value, float):
        raise EvidenceV2Error(
            f"{path} contains a float; V2 evidence uses integer units only"
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_jcs_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceV2Error(f"{path} contains a non-string object key")
            _validate_jcs_value(key, f"{path}.<key>")
            _validate_jcs_value(item, f"{path}.{key}")
        return
    raise EvidenceV2Error(f"{path} contains unsupported type {type(value).__name__}")


def canonicalize_jcs(value: Any) -> bytes:
    """Return RFC 8785 bytes after enforcing Pramagent's integer-only profile."""
    _validate_jcs_value(value)
    try:
        import rfc8785
    except ImportError as exc:  # pragma: no cover - dependency failure path
        raise EvidenceV2DependencyError(
            'V2 evidence requires rfc8785; install "pramagent[evidence-v2]"'
        ) from exc
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceV2Error(f"RFC 8785 canonicalization failed: {exc}") from exc


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str, label: str) -> bytes:
    if not isinstance(value, str):
        raise EvidenceV2Error(f"{label} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EvidenceV2Error(f"{label} is not valid base64") from exc
    if _b64encode(decoded) != value:
        raise EvidenceV2Error(f"{label} is not canonical base64")
    return decoded


@dataclass(frozen=True)
class SignaturePolicy:
    policy_version: str
    required_algorithms: tuple[str, ...]
    signature_mode: str = "all_required"

    def validate(self) -> None:
        if not self.policy_version:
            raise EvidenceV2Error("signature policy version is required")
        if self.signature_mode != "all_required":
            raise EvidenceV2Error("V2 only supports all_required signature policy")
        if not self.required_algorithms or len(set(self.required_algorithms)) != len(
            self.required_algorithms
        ):
            raise EvidenceV2Error("required signature algorithms must be unique")
        if any(not item for item in self.required_algorithms):
            raise EvidenceV2Error("signature algorithm identifiers cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "policy_version": self.policy_version,
            "required_algorithms": list(self.required_algorithms),
            "signature_mode": self.signature_mode,
        }


DEFAULT_SIGNATURE_POLICY = SignaturePolicy(
    policy_version="pramagent-hybrid-2026-01",
    required_algorithms=(ED25519, ML_DSA_65),
)
DEFAULT_SIGNATURE_POLICIES = {
    DEFAULT_SIGNATURE_POLICY.policy_version: DEFAULT_SIGNATURE_POLICY
}


@dataclass(frozen=True)
class AnchorPolicy:
    policy_version: str
    required_anchor_types: tuple[str, ...]
    validation_mode: str = "all_required"

    def validate(self) -> None:
        if not self.policy_version:
            raise EvidenceV2Error("anchor policy version is required")
        if self.validation_mode != "all_required":
            raise EvidenceV2Error("V2 only supports all_required anchor policy")
        if not self.required_anchor_types or len(set(self.required_anchor_types)) != len(
            self.required_anchor_types
        ):
            raise EvidenceV2Error("required anchor types must be unique")


DEFAULT_ANCHOR_POLICY = AnchorPolicy(
    policy_version="pramagent-external-witness-2026-01",
    required_anchor_types=("RFC3161", "transparency-log"),
)
DEFAULT_ANCHOR_POLICIES = {
    DEFAULT_ANCHOR_POLICY.policy_version: DEFAULT_ANCHOR_POLICY
}


@dataclass(frozen=True)
class EvidenceLeafV2:
    record_id: str
    sequence: int
    record_version: str
    record_digest: str
    observed_at_us: int
    nonce_b64: str
    provenance_mode: str = "native-v2"
    source_assurance: str = AssuranceLevel.CHECKSUM_ONLY.value
    record_hash_algorithm: str = "SHA-256"
    schema_version: str = SCHEMA_VERSION
    domain: str = LEAF_DOMAIN
    leaf_hash: str = ""

    @classmethod
    def create_native(
        cls,
        *,
        record_id: str,
        sequence: int,
        observed_at_us: int,
        record: dict[str, Any],
        nonce: bytes | None = None,
    ) -> "EvidenceLeafV2":
        digest = hashlib.sha256(canonicalize_jcs(record)).hexdigest()
        return cls(
            record_id=record_id,
            sequence=sequence,
            record_version=SCHEMA_VERSION,
            record_digest=digest,
            observed_at_us=observed_at_us,
            nonce_b64=_b64encode(nonce if nonce is not None else secrets.token_bytes(16)),
        ).seal()

    @classmethod
    def wrap_legacy_v1(
        cls,
        *,
        record_id: str,
        sequence: int,
        observed_at_us: int,
        record_digest: str,
        nonce: bytes | None = None,
        source_assurance: AssuranceLevel = AssuranceLevel.CHECKSUM_ONLY,
    ) -> "EvidenceLeafV2":
        if source_assurance not in {
            AssuranceLevel.CHECKSUM_ONLY,
            AssuranceLevel.HMAC_AUTHENTICATED,
        }:
            raise EvidenceV2Error("legacy source assurance cannot be asymmetric")
        return cls(
            record_id=record_id,
            sequence=sequence,
            record_version="1.0",
            record_digest=record_digest,
            observed_at_us=observed_at_us,
            nonce_b64=_b64encode(nonce if nonce is not None else secrets.token_bytes(16)),
            provenance_mode="legacy-v1-wrap",
            source_assurance=source_assurance.value,
        ).seal()

    def material(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "nonce_b64": self.nonce_b64,
            "observed_at_us": self.observed_at_us,
            "provenance_mode": self.provenance_mode,
            "record_digest": self.record_digest,
            "record_hash_algorithm": self.record_hash_algorithm,
            "record_id": self.record_id,
            "record_version": self.record_version,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "source_assurance": self.source_assurance,
        }

    def computed_hash(self) -> str:
        return hashlib.sha256(b"\x00" + canonicalize_jcs(self.material())).hexdigest()

    def seal(self) -> "EvidenceLeafV2":
        self.validate(require_hash=False)
        return EvidenceLeafV2(**self.material(), leaf_hash=self.computed_hash())

    def validate(self, *, require_hash: bool = True) -> None:
        if self.schema_version != SCHEMA_VERSION or self.domain != LEAF_DOMAIN:
            raise EvidenceV2Error("unsupported leaf schema or domain")
        if not self.record_id or not self.record_version:
            raise EvidenceV2Error("record_id and record_version are required")
        _require_safe_integer(self.sequence, "sequence")
        _require_safe_integer(self.observed_at_us, "observed_at_us", minimum=1)
        if self.record_hash_algorithm != "SHA-256" or not _valid_sha256(
            self.record_digest
        ):
            raise EvidenceV2Error("record digest must be lowercase SHA-256")
        nonce = _b64decode(self.nonce_b64, "nonce_b64")
        if len(nonce) < 16:
            raise EvidenceV2Error("leaf nonce must contain at least 128 bits")
        if self.provenance_mode not in {"native-v2", "legacy-v1-wrap"}:
            raise EvidenceV2Error("unsupported provenance_mode")
        try:
            source = AssuranceLevel(self.source_assurance)
        except ValueError as exc:
            raise EvidenceV2Error("unsupported source assurance") from exc
        if self.provenance_mode == "legacy-v1-wrap" and source not in {
            AssuranceLevel.CHECKSUM_ONLY,
            AssuranceLevel.HMAC_AUTHENTICATED,
        }:
            raise EvidenceV2Error("legacy records cannot claim asymmetric origin")
        if require_hash and self.leaf_hash != self.computed_hash():
            raise EvidenceV2Error("evidence leaf hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self.material(), "leaf_hash": self.leaf_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceLeafV2":
        expected = {
            "domain",
            "nonce_b64",
            "observed_at_us",
            "provenance_mode",
            "record_digest",
            "record_hash_algorithm",
            "record_id",
            "record_version",
            "schema_version",
            "sequence",
            "source_assurance",
            "leaf_hash",
        }
        _exact_fields(raw, expected, "evidence leaf")
        leaf = cls(**dict(raw))
        leaf.validate()
        return leaf


@dataclass(frozen=True)
class CheckpointV2:
    epoch_id: str
    tree_size: int
    first_sequence: int
    last_sequence: int
    merkle_root: str
    issued_at_us: int
    previous_checkpoint_hash: str
    signature_policy_version: str
    required_signature_algorithms: tuple[str, ...]
    anchor_policy_version: str = "pramagent-external-witness-2026-01"
    hash_algorithm: str = "SHA-256"
    merkle_algorithm: str = "PRAMAGENT-MERKLE-SHA256-V1"
    canonicalization: str = "RFC8785-JCS-INTEGER-PROFILE"
    schema_version: str = SCHEMA_VERSION
    domain: str = CHECKPOINT_DOMAIN

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.domain != CHECKPOINT_DOMAIN:
            raise EvidenceV2Error("unsupported checkpoint schema or domain")
        if not self.epoch_id:
            raise EvidenceV2Error("epoch_id is required")
        _require_safe_integer(self.tree_size, "tree_size", minimum=1)
        _require_safe_integer(self.first_sequence, "first_sequence")
        _require_safe_integer(self.last_sequence, "last_sequence")
        _require_safe_integer(self.issued_at_us, "issued_at_us", minimum=1)
        if self.last_sequence - self.first_sequence + 1 != self.tree_size:
            raise EvidenceV2Error("checkpoint sequence range does not match tree size")
        if not _valid_sha256(self.merkle_root) or not _valid_sha256(
            self.previous_checkpoint_hash
        ):
            raise EvidenceV2Error("checkpoint hashes must be lowercase SHA-256")
        if self.hash_algorithm != "SHA-256":
            raise EvidenceV2Error("unsupported checkpoint hash algorithm")
        if self.merkle_algorithm != "PRAMAGENT-MERKLE-SHA256-V1":
            raise EvidenceV2Error("unsupported Merkle algorithm")
        if self.canonicalization != "RFC8785-JCS-INTEGER-PROFILE":
            raise EvidenceV2Error("unsupported canonicalization profile")
        if not self.signature_policy_version or not self.anchor_policy_version:
            raise EvidenceV2Error("checkpoint policy versions are required")
        if not self.required_signature_algorithms or len(
            set(self.required_signature_algorithms)
        ) != len(self.required_signature_algorithms):
            raise EvidenceV2Error("required signature algorithms must be unique")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "anchor_policy_version": self.anchor_policy_version,
            "canonicalization": self.canonicalization,
            "domain": self.domain,
            "epoch_id": self.epoch_id,
            "first_sequence": self.first_sequence,
            "hash_algorithm": self.hash_algorithm,
            "issued_at_us": self.issued_at_us,
            "last_sequence": self.last_sequence,
            "merkle_algorithm": self.merkle_algorithm,
            "merkle_root": self.merkle_root,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "required_signature_algorithms": list(
                self.required_signature_algorithms
            ),
            "schema_version": self.schema_version,
            "signature_policy_version": self.signature_policy_version,
            "tree_size": self.tree_size,
        }

    def signing_bytes(self) -> bytes:
        return CHECKPOINT_SIGNATURE_PREFIX + canonicalize_jcs(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CheckpointV2":
        expected = {
            "anchor_policy_version",
            "canonicalization",
            "domain",
            "epoch_id",
            "first_sequence",
            "hash_algorithm",
            "issued_at_us",
            "last_sequence",
            "merkle_algorithm",
            "merkle_root",
            "previous_checkpoint_hash",
            "required_signature_algorithms",
            "schema_version",
            "signature_policy_version",
            "tree_size",
        }
        _exact_fields(raw, expected, "checkpoint")
        values = dict(raw)
        values["required_signature_algorithms"] = tuple(
            values["required_signature_algorithms"]
        )
        checkpoint = cls(**values)
        checkpoint.validate()
        return checkpoint


@dataclass(frozen=True)
class SignatureEntry:
    algorithm: str
    key_id: str
    signature_b64: str

    def validate(self) -> None:
        if not self.algorithm or not self.key_id:
            raise EvidenceV2Error("signature algorithm and key_id are required")
        if not _b64decode(self.signature_b64, "signature_b64"):
            raise EvidenceV2Error("signature cannot be empty")

    def to_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signature_b64": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SignatureEntry":
        _exact_fields(raw, {"algorithm", "key_id", "signature_b64"}, "signature")
        entry = cls(**dict(raw))
        entry.validate()
        return entry


@dataclass(frozen=True)
class SignedCheckpointV2:
    checkpoint: CheckpointV2
    signatures: tuple[SignatureEntry, ...]
    checkpoint_hash: str = ""

    def material(self) -> dict[str, Any]:
        return {
            "checkpoint": self.checkpoint.to_dict(),
            "signatures": [item.to_dict() for item in self.signatures],
        }

    def computed_hash(self) -> str:
        return hashlib.sha256(canonicalize_jcs(self.material())).hexdigest()

    def seal(self) -> "SignedCheckpointV2":
        self.validate(require_hash=False)
        return SignedCheckpointV2(
            checkpoint=self.checkpoint,
            signatures=self.signatures,
            checkpoint_hash=self.computed_hash(),
        )

    def validate(self, *, require_hash: bool = True) -> None:
        self.checkpoint.validate()
        if not self.signatures:
            raise EvidenceV2Error("checkpoint needs signatures")
        for signature in self.signatures:
            signature.validate()
        if require_hash and self.checkpoint_hash != self.computed_hash():
            raise EvidenceV2Error("signed checkpoint hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self.material(), "checkpoint_hash": self.checkpoint_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SignedCheckpointV2":
        _exact_fields(
            raw, {"checkpoint", "signatures", "checkpoint_hash"}, "signed checkpoint"
        )
        signed = cls(
            checkpoint=CheckpointV2.from_dict(raw["checkpoint"]),
            signatures=tuple(
                SignatureEntry.from_dict(item) for item in raw["signatures"]
            ),
            checkpoint_hash=raw["checkpoint_hash"],
        )
        signed.validate()
        return signed


@dataclass(frozen=True)
class VerificationKey:
    algorithm: str
    key_id: str
    public_key_b64: str

    @property
    def public_key(self) -> bytes:
        return _b64decode(self.public_key_b64, "public_key_b64")

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key_b64": self.public_key_b64,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "VerificationKey":
        _exact_fields(raw, {"algorithm", "key_id", "public_key_b64"}, "key")
        key = cls(**dict(raw))
        if not key.algorithm or not key.key_id or not key.public_key:
            raise EvidenceV2Error("verification key is incomplete")
        return key


@dataclass(frozen=True)
class HybridCheckpointSigner:
    ed25519_key_id: str
    ml_dsa_65_key_id: str
    ed25519_private_key: bytes = field(repr=False)
    ml_dsa_65_private_key: bytes = field(repr=False)
    ml_dsa_65_public_key: bytes = field(repr=False)

    @classmethod
    def generate(
        cls,
        *,
        ed25519_key_id: str,
        ml_dsa_65_key_id: str,
    ) -> "HybridCheckpointSigner":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from pqcrypto.sign import ml_dsa_65
        except ImportError as exc:  # pragma: no cover - dependency failure path
            raise EvidenceV2DependencyError(
                'hybrid signing requires "pramagent[evidence-v2]"'
            ) from exc
        ed_private = Ed25519PrivateKey.generate().private_bytes_raw()
        ml_public, ml_private = ml_dsa_65.keygen()
        return cls(
            ed25519_key_id=ed25519_key_id,
            ml_dsa_65_key_id=ml_dsa_65_key_id,
            ed25519_private_key=ed_private,
            ml_dsa_65_private_key=ml_private,
            ml_dsa_65_public_key=ml_public,
        )

    def public_keys(self) -> tuple[VerificationKey, VerificationKey]:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:  # pragma: no cover - dependency failure path
            raise EvidenceV2DependencyError(
                'hybrid signing requires "pramagent[evidence-v2]"'
            ) from exc
        ed_public = Ed25519PrivateKey.from_private_bytes(
            self.ed25519_private_key
        ).public_key().public_bytes_raw()
        return (
            VerificationKey(ED25519, self.ed25519_key_id, _b64encode(ed_public)),
            VerificationKey(
                ML_DSA_65,
                self.ml_dsa_65_key_id,
                _b64encode(self.ml_dsa_65_public_key),
            ),
        )

    def sign(
        self,
        checkpoint: CheckpointV2,
        *,
        policy: SignaturePolicy = DEFAULT_SIGNATURE_POLICY,
    ) -> SignedCheckpointV2:
        policy.validate()
        checkpoint.validate()
        if checkpoint.signature_policy_version != policy.policy_version or tuple(
            checkpoint.required_signature_algorithms
        ) != tuple(policy.required_algorithms):
            raise EvidenceV2Error("checkpoint does not match signing policy")
        if set(policy.required_algorithms) != {ED25519, ML_DSA_65}:
            raise EvidenceV2Error("this signer implements the Ed25519/ML-DSA-65 policy")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from pqcrypto.sign import ml_dsa_65
        except ImportError as exc:  # pragma: no cover - dependency failure path
            raise EvidenceV2DependencyError(
                'hybrid signing requires "pramagent[evidence-v2]"'
            ) from exc
        material = checkpoint.signing_bytes()
        signatures = {
            ED25519: SignatureEntry(
                ED25519,
                self.ed25519_key_id,
                _b64encode(
                    Ed25519PrivateKey.from_private_bytes(
                        self.ed25519_private_key
                    ).sign(material)
                ),
            ),
            ML_DSA_65: SignatureEntry(
                ML_DSA_65,
                self.ml_dsa_65_key_id,
                _b64encode(ml_dsa_65.sign(self.ml_dsa_65_private_key, material)),
            ),
        }
        return SignedCheckpointV2(
            checkpoint=checkpoint,
            signatures=tuple(signatures[item] for item in policy.required_algorithms),
        ).seal()


@dataclass(frozen=True)
class CheckpointVerification:
    valid: bool
    verified_algorithms: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "verified_algorithms": list(self.verified_algorithms),
            "errors": list(self.errors),
        }


def verify_signed_checkpoint(
    signed: SignedCheckpointV2,
    *,
    trusted_keys: Mapping[tuple[str, str], bytes],
    trusted_policies: Mapping[str, SignaturePolicy] = DEFAULT_SIGNATURE_POLICIES,
    previous_checkpoint: SignedCheckpointV2 | None = None,
) -> CheckpointVerification:
    errors: list[str] = []
    verified: list[str] = []
    checkpoint = signed.checkpoint
    try:
        checkpoint.validate()
    except EvidenceV2Error as exc:
        return CheckpointVerification(False, (), (str(exc),))

    policy = trusted_policies.get(checkpoint.signature_policy_version)
    if policy is None:
        errors.append("signature policy is not trusted")
    else:
        try:
            policy.validate()
        except EvidenceV2Error as exc:
            errors.append(str(exc))
        if tuple(checkpoint.required_signature_algorithms) != tuple(
            policy.required_algorithms
        ):
            errors.append("checkpoint algorithm set does not match trusted policy")
        if policy.signature_mode != "all_required":
            errors.append("trusted policy does not require every signature")

    by_algorithm: dict[str, SignatureEntry] = {}
    for signature in signed.signatures:
        try:
            signature.validate()
        except EvidenceV2Error as exc:
            errors.append(str(exc))
        if signature.algorithm in by_algorithm:
            errors.append(f"duplicate {signature.algorithm} signature")
        by_algorithm[signature.algorithm] = signature
    expected = set(policy.required_algorithms) if policy is not None else set()
    missing = sorted(expected - set(by_algorithm))
    unexpected = sorted(set(by_algorithm) - expected)
    if missing:
        errors.append(f"missing required signatures: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unexpected signatures: {', '.join(unexpected)}")
    if errors:
        return CheckpointVerification(False, (), tuple(dict.fromkeys(errors)))

    if signed.checkpoint_hash != signed.computed_hash():
        return CheckpointVerification(False, (), ("signed checkpoint hash mismatch",))

    if previous_checkpoint is None:
        if checkpoint.previous_checkpoint_hash != GENESIS_CHECKPOINT_HASH:
            errors.append("first checkpoint does not reference genesis")
    else:
        try:
            previous_checkpoint.validate()
        except EvidenceV2Error as exc:
            errors.append(f"previous checkpoint is invalid: {exc}")
        if checkpoint.previous_checkpoint_hash != previous_checkpoint.checkpoint_hash:
            errors.append("checkpoint does not link to previous checkpoint")
        if checkpoint.issued_at_us <= previous_checkpoint.checkpoint.issued_at_us:
            errors.append("checkpoint time does not advance")
        if checkpoint.last_sequence <= previous_checkpoint.checkpoint.last_sequence:
            errors.append("checkpoint sequence does not advance")

    material = checkpoint.signing_bytes()
    if not errors:
        for algorithm in policy.required_algorithms:
            signature = by_algorithm[algorithm]
            public_key = trusted_keys.get((algorithm, signature.key_id))
            if public_key is None:
                errors.append(f"untrusted key {algorithm}:{signature.key_id}")
                continue
            try:
                raw_signature = _b64decode(signature.signature_b64, "signature_b64")
                if algorithm == ED25519:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                        Ed25519PublicKey,
                    )

                    Ed25519PublicKey.from_public_bytes(public_key).verify(
                        raw_signature, material
                    )
                elif algorithm == ML_DSA_65:
                    from pqcrypto.sign import ml_dsa_65

                    ml_dsa_65.verify(public_key, material, raw_signature)
                else:
                    raise EvidenceV2Error(f"unsupported algorithm {algorithm}")
                verified.append(algorithm)
            except ImportError as exc:
                errors.append(f"dependency unavailable for {algorithm}: {exc}")
            except Exception:
                errors.append(f"invalid {algorithm} signature")
    return CheckpointVerification(not errors, tuple(verified), tuple(errors))


@dataclass(frozen=True)
class ExternalAnchorV2:
    anchor_type: str
    witness_id: str
    checkpoint_hash: str
    issued_at_us: int
    artifact_b64: str
    certificate_chain_b64: tuple[str, ...] = ()
    revocation_material_b64: tuple[str, ...] = ()
    anchor_id: str = ""

    def validate(self) -> None:
        if self.anchor_type not in {"RFC3161", "transparency-log"}:
            raise EvidenceV2Error("unsupported external anchor type")
        if not self.witness_id or not self.anchor_id:
            raise EvidenceV2Error("external anchor witness and ID are required")
        if not _valid_sha256(self.checkpoint_hash):
            raise EvidenceV2Error("external anchor checkpoint hash is invalid")
        _require_safe_integer(self.issued_at_us, "anchor issued_at_us", minimum=1)
        if not _b64decode(self.artifact_b64, "anchor artifact"):
            raise EvidenceV2Error("external anchor artifact cannot be empty")
        for item in self.certificate_chain_b64:
            if not _b64decode(item, "anchor certificate"):
                raise EvidenceV2Error("anchor certificate cannot be empty")
        for item in self.revocation_material_b64:
            if not _b64decode(item, "anchor revocation material"):
                raise EvidenceV2Error("anchor revocation material cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "anchor_id": self.anchor_id,
            "anchor_type": self.anchor_type,
            "artifact_b64": self.artifact_b64,
            "certificate_chain_b64": list(self.certificate_chain_b64),
            "checkpoint_hash": self.checkpoint_hash,
            "issued_at_us": self.issued_at_us,
            "revocation_material_b64": list(self.revocation_material_b64),
            "witness_id": self.witness_id,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExternalAnchorV2":
        expected = {
            "anchor_id",
            "anchor_type",
            "artifact_b64",
            "certificate_chain_b64",
            "checkpoint_hash",
            "issued_at_us",
            "revocation_material_b64",
            "witness_id",
        }
        _exact_fields(raw, expected, "external anchor")
        values = dict(raw)
        values["certificate_chain_b64"] = tuple(values["certificate_chain_b64"])
        values["revocation_material_b64"] = tuple(
            values["revocation_material_b64"]
        )
        anchor = cls(**values)
        anchor.validate()
        return anchor


AnchorVerifier = Callable[[ExternalAnchorV2], bool]


@dataclass(frozen=True)
class EvidenceVerificationReport:
    valid: bool
    assurance_level: str
    record_assurance: str
    checkpoint_assurance: str
    checkpoint: CheckpointVerification
    inclusion_valid: bool
    tsa_valid: bool
    publication_valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "assurance_level": self.assurance_level,
            "checkpoint": self.checkpoint.to_dict(),
            "checkpoint_assurance": self.checkpoint_assurance,
            "errors": list(self.errors),
            "inclusion_valid": self.inclusion_valid,
            "publication_valid": self.publication_valid,
            "record_assurance": self.record_assurance,
            "tsa_valid": self.tsa_valid,
            "valid": self.valid,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class EvidenceEnvelopeV2:
    leaf: EvidenceLeafV2
    checkpoint: SignedCheckpointV2
    inclusion_proof: tuple[str, ...]
    record: dict[str, Any] | None = None
    anchors: tuple[ExternalAnchorV2, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchors": [anchor.to_dict() for anchor in self.anchors],
            "checkpoint": self.checkpoint.to_dict(),
            "inclusion_proof": list(self.inclusion_proof),
            "leaf": self.leaf.to_dict(),
            "record": self.record,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceEnvelopeV2":
        _exact_fields(
            raw,
            {"anchors", "checkpoint", "inclusion_proof", "leaf", "record"},
            "evidence envelope",
        )
        return cls(
            leaf=EvidenceLeafV2.from_dict(raw["leaf"]),
            checkpoint=SignedCheckpointV2.from_dict(raw["checkpoint"]),
            inclusion_proof=tuple(raw["inclusion_proof"]),
            record=raw["record"],
            anchors=tuple(ExternalAnchorV2.from_dict(item) for item in raw["anchors"]),
        )

    @classmethod
    def from_json(cls, encoded: str | bytes) -> "EvidenceEnvelopeV2":
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise EvidenceV2Error(f"duplicate JSON property {key!r}")
                result[key] = value
            return result

        try:
            raw = json.loads(encoded, object_pairs_hook=reject_duplicates)
        except EvidenceV2Error:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceV2Error(f"invalid evidence envelope JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise EvidenceV2Error("evidence envelope JSON must contain an object")
        return cls.from_dict(raw)

    def verify(
        self,
        *,
        trusted_keys: Mapping[tuple[str, str], bytes],
        trusted_policies: Mapping[str, SignaturePolicy] = DEFAULT_SIGNATURE_POLICIES,
        trusted_anchor_policies: Mapping[str, AnchorPolicy] = DEFAULT_ANCHOR_POLICIES,
        anchor_verifiers: Mapping[str, AnchorVerifier] | None = None,
        previous_checkpoint: SignedCheckpointV2 | None = None,
        required_assurance: AssuranceLevel = AssuranceLevel.CHECKSUM_ONLY,
    ) -> EvidenceVerificationReport:
        from .merkle import verify_inclusion_proof

        errors: list[str] = []
        warnings: list[str] = []
        try:
            self.leaf.validate()
        except EvidenceV2Error as exc:
            errors.append(str(exc))
        if self.leaf.provenance_mode == "native-v2":
            if self.record is None:
                errors.append("native V2 envelope does not contain its record")
            else:
                try:
                    digest = hashlib.sha256(canonicalize_jcs(self.record)).hexdigest()
                    if digest != self.leaf.record_digest:
                        errors.append("record digest does not match evidence leaf")
                except EvidenceV2Error as exc:
                    errors.append(str(exc))
        elif self.record is not None:
            warnings.append(
                "legacy record bytes are not re-canonicalized by the V2 verifier"
            )

        checkpoint_result = verify_signed_checkpoint(
            self.checkpoint,
            trusted_keys=trusted_keys,
            trusted_policies=trusted_policies,
            previous_checkpoint=previous_checkpoint,
        )
        if not checkpoint_result.valid:
            errors.extend(checkpoint_result.errors)
        checkpoint = self.checkpoint.checkpoint
        anchor_policy = trusted_anchor_policies.get(checkpoint.anchor_policy_version)
        if anchor_policy is None:
            errors.append("external anchor policy is not trusted")
        else:
            try:
                anchor_policy.validate()
            except EvidenceV2Error as exc:
                errors.append(str(exc))
        try:
            inclusion_valid = verify_inclusion_proof(
                self.leaf.leaf_hash,
                self.leaf.sequence - self.checkpoint.checkpoint.first_sequence,
                self.checkpoint.checkpoint.tree_size,
                self.inclusion_proof,
                self.checkpoint.checkpoint.merkle_root,
            )
        except EvidenceV2Error as exc:
            inclusion_valid = False
            errors.append(str(exc))
        if not inclusion_valid:
            errors.append("Merkle inclusion proof is invalid")

        tsa_valid = False
        publication_valid = False
        verifiers = anchor_verifiers or {}
        for anchor in self.anchors:
            try:
                anchor.validate()
            except EvidenceV2Error as exc:
                errors.append(str(exc))
                continue
            if anchor.checkpoint_hash != self.checkpoint.checkpoint_hash:
                errors.append("external anchor references another checkpoint")
                continue
            if anchor.issued_at_us < checkpoint.issued_at_us:
                errors.append("external anchor predates checkpoint issuance")
                continue
            verifier = verifiers.get(anchor.anchor_type)
            if verifier is None:
                warnings.append(f"no verifier configured for {anchor.anchor_type}")
                continue
            try:
                verified = bool(verifier(anchor))
            except Exception as exc:
                errors.append(f"{anchor.anchor_type} verifier failed: {exc}")
                continue
            if not verified:
                errors.append(f"{anchor.anchor_type} anchor is invalid")
            elif anchor.anchor_type == "RFC3161":
                tsa_valid = True
            elif anchor.anchor_type == "transparency-log":
                publication_valid = True

        checkpoint_assurance = AssuranceLevel.CHECKSUM_ONLY
        if checkpoint_result.valid and inclusion_valid:
            checkpoint_assurance = AssuranceLevel.ASYMMETRIC_CHECKPOINTED
        anchors_satisfied = bool(anchor_policy) and all(
            {
                "RFC3161": tsa_valid,
                "transparency-log": publication_valid,
            }.get(anchor_type, False)
            for anchor_type in anchor_policy.required_anchor_types
        )
        if checkpoint_assurance == AssuranceLevel.ASYMMETRIC_CHECKPOINTED:
            if anchors_satisfied:
                checkpoint_assurance = AssuranceLevel.TSA_ANCHORED
            elif tsa_valid:
                warnings.append(
                    "timestamp is valid but lacks an independently verified publication"
                )

        record_assurance = AssuranceLevel(self.leaf.source_assurance)
        if self.leaf.provenance_mode == "legacy-v1-wrap":
            assurance = record_assurance
            warnings.append(
                "legacy wrapping proves checkpoint-time inclusion, not original authorship"
            )
        else:
            assurance = checkpoint_assurance
        if _ASSURANCE_RANK[assurance] < _ASSURANCE_RANK[required_assurance]:
            errors.append(
                f"assurance {assurance.value} is below required {required_assurance.value}"
            )
        return EvidenceVerificationReport(
            valid=not errors,
            assurance_level=assurance.value,
            record_assurance=record_assurance.value,
            checkpoint_assurance=checkpoint_assurance.value,
            checkpoint=checkpoint_result,
            inclusion_valid=inclusion_valid,
            tsa_valid=tsa_valid,
            publication_valid=publication_valid,
            errors=tuple(errors),
            warnings=tuple(dict.fromkeys(warnings)),
        )


__all__ = [
    "AnchorPolicy",
    "AssuranceLevel",
    "CheckpointV2",
    "DEFAULT_ANCHOR_POLICIES",
    "DEFAULT_ANCHOR_POLICY",
    "DEFAULT_SIGNATURE_POLICIES",
    "DEFAULT_SIGNATURE_POLICY",
    "ED25519",
    "EvidenceEnvelopeV2",
    "EvidenceLeafV2",
    "EvidenceV2DependencyError",
    "EvidenceV2Error",
    "EvidenceVerificationReport",
    "ExternalAnchorV2",
    "GENESIS_CHECKPOINT_HASH",
    "HybridCheckpointSigner",
    "ML_DSA_65",
    "SCHEMA_VERSION",
    "SignatureEntry",
    "SignaturePolicy",
    "SignedCheckpointV2",
    "VerificationKey",
    "canonicalize_jcs",
    "verify_signed_checkpoint",
]
