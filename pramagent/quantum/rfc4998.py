"""Minimal RFC 4998 Evidence Record Syntax and timestamp renewal support.

The implementation covers one archived data object, RFC 3161 timestamps, and
timestamp renewal within one ArchiveTimeStampChain. Hash-tree renewal is a
separate operation and is deliberately not implied by this module.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import replace
from dataclasses import dataclass
from typing import Any, Callable

from .anchors import RFC3161_ANCHOR_DOMAIN, RFC3161_ARTIFACT_VERSION
from .evidence_v2 import ExternalAnchorV2

SHA256_OID = "2.16.840.1.101.3.4.2.1"


class RFC4998Error(ValueError):
    """Raised when an Evidence Record is malformed or has a broken binding."""


def _dependencies() -> tuple[Any, ...]:
    try:
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type import namedtype, tag, univ
        from pyasn1_modules import rfc3161, rfc5280, rfc5652
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError(
            'RFC 4998 support requires "pramagent[evidence-anchors]"'
        ) from exc
    return decoder, encoder, namedtype, tag, univ, rfc3161, rfc5280, rfc5652


def _types() -> dict[str, Any]:
    _, _, namedtype, tag, univ, _, rfc5280, rfc5652 = _dependencies()

    class PartialHashtree(univ.SequenceOf):
        componentType = univ.OctetString()

    class ReducedHashtree(univ.SequenceOf):
        componentType = PartialHashtree()

    class Attributes(univ.SetOf):
        componentType = rfc5652.Attribute()

    class ArchiveTimeStamp(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType(
                "digestAlgorithm",
                rfc5280.AlgorithmIdentifier().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0
                    )
                ),
            ),
            namedtype.OptionalNamedType(
                "attributes",
                Attributes().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 1
                    )
                ),
            ),
            namedtype.OptionalNamedType(
                "reducedHashtree",
                ReducedHashtree().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 2
                    )
                ),
            ),
            namedtype.NamedType("timeStamp", rfc5652.ContentInfo()),
        )

    class ArchiveTimeStampChain(univ.SequenceOf):
        componentType = ArchiveTimeStamp()

    class ArchiveTimeStampSequence(univ.SequenceOf):
        componentType = ArchiveTimeStampChain()

    class DigestAlgorithms(univ.SequenceOf):
        componentType = rfc5280.AlgorithmIdentifier()

    class EvidenceRecord(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType("digestAlgorithms", DigestAlgorithms()),
            namedtype.NamedType(
                "archiveTimeStampSequence", ArchiveTimeStampSequence()
            ),
        )

    return {
        "ArchiveTimeStamp": ArchiveTimeStamp,
        "ArchiveTimeStampChain": ArchiveTimeStampChain,
        "ArchiveTimeStampSequence": ArchiveTimeStampSequence,
        "DigestAlgorithms": DigestAlgorithms,
        "EvidenceRecord": EvidenceRecord,
    }


def _decode_complete(encoded: bytes, spec: Any, label: str) -> Any:
    decoder, _, *_ = _dependencies()
    try:
        value, trailing = decoder.decode(encoded, asn1Spec=spec)
    except Exception as exc:
        raise RFC4998Error(f"invalid DER {label}") from exc
    if trailing:
        raise RFC4998Error(f"DER {label} has trailing data")
    return value


def _sha256_algorithm() -> Any:
    dependencies = _dependencies()
    rfc5280 = dependencies[6]
    algorithm = rfc5280.AlgorithmIdentifier()
    algorithm["algorithm"] = SHA256_OID
    algorithm["parameters"] = b"\x05\x00"
    return algorithm


def _response_der(anchor: ExternalAnchorV2) -> bytes:
    if anchor.anchor_type != "RFC3161":
        raise RFC4998Error("RFC 4998 requires an RFC 3161 anchor")
    try:
        artifact = json.loads(base64.b64decode(anchor.artifact_b64, validate=True))
        if artifact["artifact_version"] != RFC3161_ARTIFACT_VERSION:
            raise RFC4998Error("unsupported RFC 3161 artifact version")
        return base64.b64decode(artifact["response_b64"], validate=True)
    except RFC4998Error:
        raise
    except Exception as exc:
        raise RFC4998Error("invalid RFC 3161 anchor artifact") from exc


def _timestamp_token(response_der: bytes) -> Any:
    dependencies = _dependencies()
    rfc3161 = dependencies[5]
    response = _decode_complete(response_der, rfc3161.TimeStampResp(), "response")
    status = int(response["status"]["status"])
    if status not in {0, 1} or not response["timeStampToken"].hasValue():
        raise RFC4998Error("RFC 3161 response does not contain a granted token")
    return response["timeStampToken"]


def _token_imprint(token: Any) -> tuple[str, bytes]:
    dependencies = _dependencies()
    decoder = dependencies[0]
    rfc3161 = dependencies[5]
    rfc5652 = dependencies[7]
    try:
        signed_data, trailing = decoder.decode(
            token["content"].asOctets(), asn1Spec=rfc5652.SignedData()
        )
        if trailing:
            raise RFC4998Error("timestamp SignedData has trailing bytes")
        content = signed_data["encapContentInfo"]["eContent"].asOctets()
        tst_info, trailing = decoder.decode(content, asn1Spec=rfc3161.TSTInfo())
        if trailing:
            raise RFC4998Error("timestamp TSTInfo has trailing bytes")
        imprint = tst_info["messageImprint"]
        return (
            str(imprint["hashAlgorithm"]["algorithm"]),
            bytes(imprint["hashedMessage"]),
        )
    except RFC4998Error:
        raise
    except Exception as exc:
        raise RFC4998Error("cannot read timestamp message imprint") from exc


def _token_der(token: Any) -> bytes:
    _, encoder, *_ = _dependencies()
    return encoder.encode(token)


def _assert_sha256_binding(token: Any, payload: bytes) -> None:
    algorithm, digest = _token_imprint(token)
    if algorithm != SHA256_OID:
        raise RFC4998Error(f"unsupported timestamp digest algorithm {algorithm}")
    if digest != hashlib.sha256(payload).digest():
        raise RFC4998Error("timestamp message imprint does not bind the payload")


@dataclass(frozen=True)
class RFC4998VerificationReport:
    valid: bool
    timestamp_count: int
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class RFC4998ArchiveBundle:
    """Portable container retaining ERS bytes and each validation artifact."""

    checkpoint_hash: str
    archived_object_b64: str
    evidence_record_der_b64: str
    timestamp_anchors: tuple[ExternalAnchorV2, ...]
    created_at_us: int
    updated_at_us: int
    bundle_version: str = "pramagent-rfc4998-bundle-v1"
    bundle_hash: str = ""

    def material(self) -> dict[str, Any]:
        return {
            "archived_object_b64": self.archived_object_b64,
            "bundle_version": self.bundle_version,
            "checkpoint_hash": self.checkpoint_hash,
            "created_at_us": self.created_at_us,
            "evidence_record_der_b64": self.evidence_record_der_b64,
            "timestamp_anchors": [
                anchor.to_dict() for anchor in self.timestamp_anchors
            ],
            "updated_at_us": self.updated_at_us,
        }

    def computed_hash(self) -> str:
        from .evidence_v2 import canonicalize_jcs

        return hashlib.sha256(canonicalize_jcs(self.material())).hexdigest()

    def seal(self) -> "RFC4998ArchiveBundle":
        return replace(self, bundle_hash=self.computed_hash())

    def validate(self) -> None:
        if self.bundle_version != "pramagent-rfc4998-bundle-v1":
            raise RFC4998Error("unsupported RFC 4998 bundle version")
        archived = base64.b64decode(self.archived_object_b64, validate=True)
        record = base64.b64decode(self.evidence_record_der_b64, validate=True)
        if not archived or not record or not self.timestamp_anchors:
            raise RFC4998Error("RFC 4998 bundle is incomplete")
        if self.updated_at_us < self.created_at_us or self.created_at_us <= 0:
            raise RFC4998Error("RFC 4998 bundle timestamps are invalid")
        if self.bundle_hash != self.computed_hash():
            raise RFC4998Error("RFC 4998 bundle hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self.material(), "bundle_hash": self.bundle_hash}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RFC4998ArchiveBundle":
        expected = {
            "archived_object_b64",
            "bundle_hash",
            "bundle_version",
            "checkpoint_hash",
            "created_at_us",
            "evidence_record_der_b64",
            "timestamp_anchors",
            "updated_at_us",
        }
        if set(raw) != expected:
            raise RFC4998Error("RFC 4998 bundle fields do not match schema")
        values = dict(raw)
        values["timestamp_anchors"] = tuple(
            ExternalAnchorV2.from_dict(item) for item in values["timestamp_anchors"]
        )
        bundle = cls(**values)
        bundle.validate()
        return bundle

    @classmethod
    def from_json(cls, encoded: str | bytes) -> "RFC4998ArchiveBundle":
        try:
            raw = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RFC4998Error("invalid RFC 4998 bundle JSON") from exc
        if not isinstance(raw, dict):
            raise RFC4998Error("RFC 4998 bundle must be an object")
        return cls.from_dict(raw)


@dataclass(frozen=True)
class RFC4998BundleVerificationReport:
    valid: bool
    structural_valid: bool
    external_timestamps_valid: bool
    timestamp_count: int
    errors: tuple[str, ...] = ()


def checkpoint_archived_object(checkpoint_hash: str) -> bytes:
    """Return the exact object bound by a normal Pramagent TSA anchor."""
    try:
        digest = bytes.fromhex(checkpoint_hash)
    except ValueError as exc:
        raise RFC4998Error("checkpoint hash must be SHA-256 hex") from exc
    if len(digest) != 32 or checkpoint_hash != checkpoint_hash.lower():
        raise RFC4998Error("checkpoint hash must be lowercase SHA-256 hex")
    return RFC3161_ANCHOR_DOMAIN + digest


def create_archive_bundle(
    checkpoint_hash: str,
    anchor: ExternalAnchorV2,
    *,
    anchor_verifier: Callable[[ExternalAnchorV2], bool],
    now_us: int | None = None,
) -> RFC4998ArchiveBundle:
    """Create a portable archive bundle for one signed checkpoint."""
    if anchor.checkpoint_hash != checkpoint_hash:
        raise RFC4998Error("initial anchor belongs to another checkpoint")
    archived = checkpoint_archived_object(checkpoint_hash)
    record = create_evidence_record(
        archived, anchor, anchor_verifier=anchor_verifier
    )
    current = now_us if now_us is not None else time.time_ns() // 1_000
    return RFC4998ArchiveBundle(
        checkpoint_hash=checkpoint_hash,
        archived_object_b64=base64.b64encode(archived).decode("ascii"),
        evidence_record_der_b64=base64.b64encode(record).decode("ascii"),
        timestamp_anchors=(anchor,),
        created_at_us=current,
        updated_at_us=current,
    ).seal()


def renew_archive_bundle(
    bundle: RFC4998ArchiveBundle,
    renewal_anchor: ExternalAnchorV2,
    *,
    anchor_verifier: Callable[[ExternalAnchorV2], bool],
    now_us: int | None = None,
) -> RFC4998ArchiveBundle:
    """Append a verified timestamp renewal while retaining its LTV material."""
    bundle.validate()
    record = base64.b64decode(bundle.evidence_record_der_b64, validate=True)
    renewed = append_timestamp_renewal(
        record, renewal_anchor, anchor_verifier=anchor_verifier
    )
    current = now_us if now_us is not None else time.time_ns() // 1_000
    if current <= bundle.updated_at_us:
        raise RFC4998Error("archive renewal time must advance")
    return RFC4998ArchiveBundle(
        checkpoint_hash=bundle.checkpoint_hash,
        archived_object_b64=bundle.archived_object_b64,
        evidence_record_der_b64=base64.b64encode(renewed).decode("ascii"),
        timestamp_anchors=(*bundle.timestamp_anchors, renewal_anchor),
        created_at_us=bundle.created_at_us,
        updated_at_us=current,
    ).seal()


def verify_archive_bundle(
    bundle: RFC4998ArchiveBundle,
    *,
    initial_anchor_verifier: Callable[[ExternalAnchorV2], bool],
    renewal_anchor_verifier: Callable[[ExternalAnchorV2, bytes], bool],
) -> RFC4998BundleVerificationReport:
    """Verify the bundle hash, ERS links, and retained timestamp artifacts."""
    errors: list[str] = []
    structural_valid = False
    external_valid = False
    timestamp_count = 0
    try:
        bundle.validate()
        archived = base64.b64decode(bundle.archived_object_b64, validate=True)
        record = base64.b64decode(bundle.evidence_record_der_b64, validate=True)
        report = verify_evidence_record(record, archived)
        structural_valid = report.valid
        timestamp_count = report.timestamp_count
        errors.extend(report.errors)
        if timestamp_count != len(bundle.timestamp_anchors):
            errors.append("timestamp artifact count does not match EvidenceRecord")
        elif not initial_anchor_verifier(bundle.timestamp_anchors[0]):
            errors.append("initial RFC 3161 timestamp verification failed")
        else:
            current_record = create_evidence_record(
                archived,
                bundle.timestamp_anchors[0],
                anchor_verifier=initial_anchor_verifier,
            )
            for anchor in bundle.timestamp_anchors[1:]:
                payload = timestamp_renewal_payload(current_record)
                if not renewal_anchor_verifier(anchor, payload):
                    errors.append("renewal RFC 3161 timestamp verification failed")
                    break
                current_record = append_timestamp_renewal(
                    current_record,
                    anchor,
                    anchor_verifier=lambda _anchor: True,
                )
            external_valid = not errors and current_record == record
            if not errors and not external_valid:
                errors.append("retained timestamps do not reproduce EvidenceRecord")
    except RFC4998Error as exc:
        errors.append(str(exc))
    return RFC4998BundleVerificationReport(
        valid=structural_valid and external_valid and not errors,
        structural_valid=structural_valid,
        external_timestamps_valid=external_valid,
        timestamp_count=timestamp_count,
        errors=tuple(errors),
    )


def create_evidence_record(
    archived_object: bytes,
    anchor: ExternalAnchorV2,
    *,
    anchor_verifier: Callable[[ExternalAnchorV2], bool],
) -> bytes:
    """Create a DER EvidenceRecord after independently verifying its anchor."""
    if not archived_object:
        raise RFC4998Error("archived object cannot be empty")
    if not anchor_verifier(anchor):
        raise RFC4998Error("RFC 3161 anchor verification failed")
    token = _timestamp_token(_response_der(anchor))
    _assert_sha256_binding(token, archived_object)
    types = _types()
    record = types["EvidenceRecord"]()
    record["version"] = 1
    record["digestAlgorithms"].append(_sha256_algorithm())
    stamp = types["ArchiveTimeStamp"]()
    stamp["timeStamp"] = token
    chain = types["ArchiveTimeStampChain"]()
    chain.append(stamp)
    record["archiveTimeStampSequence"].append(chain)
    _, encoder, *_ = _dependencies()
    return encoder.encode(record)


def timestamp_renewal_payload(evidence_record_der: bytes) -> bytes:
    """Return the previous timeStamp ContentInfo bytes required by RFC 4998."""
    record = _decode_complete(
        evidence_record_der, _types()["EvidenceRecord"](), "EvidenceRecord"
    )
    sequence = record["archiveTimeStampSequence"]
    if not sequence or not sequence[-1]:
        raise RFC4998Error("EvidenceRecord has no archive timestamp")
    return _token_der(sequence[-1][-1]["timeStamp"])


def append_timestamp_renewal(
    evidence_record_der: bytes,
    renewal_anchor: ExternalAnchorV2,
    *,
    anchor_verifier: Callable[[ExternalAnchorV2], bool],
) -> bytes:
    """Append one RFC 4998 timestamp renewal to the current chain."""
    if not anchor_verifier(renewal_anchor):
        raise RFC4998Error("renewal RFC 3161 anchor verification failed")
    previous_timestamp = timestamp_renewal_payload(evidence_record_der)
    token = _timestamp_token(_response_der(renewal_anchor))
    _assert_sha256_binding(token, previous_timestamp)
    types = _types()
    record = _decode_complete(
        evidence_record_der, types["EvidenceRecord"](), "EvidenceRecord"
    )
    stamp = types["ArchiveTimeStamp"]()
    stamp["timeStamp"] = token
    record["archiveTimeStampSequence"][-1].append(stamp)
    _, encoder, *_ = _dependencies()
    return encoder.encode(record)


def verify_evidence_record(
    evidence_record_der: bytes, archived_object: bytes
) -> RFC4998VerificationReport:
    """Verify DER structure and every RFC 3161 message-imprint link.

    TSA signatures and certificate status are intentionally outside this
    structural verifier and must be checked against retained trust material.
    """
    errors: list[str] = []
    count = 0
    try:
        record = _decode_complete(
            evidence_record_der, _types()["EvidenceRecord"](), "EvidenceRecord"
        )
        if int(record["version"]) != 1:
            errors.append("unsupported EvidenceRecord version")
        algorithms = [
            str(item["algorithm"]) for item in record["digestAlgorithms"]
        ]
        if algorithms != [SHA256_OID]:
            errors.append("EvidenceRecord digest algorithm set is unsupported")
        sequence = record["archiveTimeStampSequence"]
        if len(sequence) != 1 or not sequence[0]:
            errors.append("timestamp-renewal profile requires one non-empty chain")
        else:
            payload = archived_object
            for stamp in sequence[0]:
                token = stamp["timeStamp"]
                _assert_sha256_binding(token, payload)
                payload = _token_der(token)
                count += 1
    except RFC4998Error as exc:
        errors.append(str(exc))
    except Exception as exc:
        errors.append(f"invalid EvidenceRecord: {exc}")
    return RFC4998VerificationReport(not errors, count, tuple(errors))


__all__ = [
    "RFC4998Error",
    "RFC4998ArchiveBundle",
    "RFC4998BundleVerificationReport",
    "RFC4998VerificationReport",
    "append_timestamp_renewal",
    "checkpoint_archived_object",
    "create_archive_bundle",
    "create_evidence_record",
    "renew_archive_bundle",
    "timestamp_renewal_payload",
    "verify_evidence_record",
    "verify_archive_bundle",
]
