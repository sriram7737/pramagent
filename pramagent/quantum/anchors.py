"""External timestamp and publication anchors for Evidence Envelope V2.

Anchoring is intentionally off the request path. The provider obtains trust
configuration through Sigstore's TUF repository, verifies every response
before returning it, and stores complete witness artifacts for later checks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .evidence_v2 import (
    EvidenceEnvelopeV2,
    EvidenceV2DependencyError,
    EvidenceV2Error,
    ExternalAnchorV2,
    SignedCheckpointV2,
    canonicalize_jcs,
)


RFC3161_ANCHOR_DOMAIN = b"pramagent:evidence-anchor:rfc3161:v2\x00"
TRANSPARENCY_ANCHOR_DOMAIN = b"pramagent:evidence-anchor:transparency:v2\x00"
RFC3161_ARTIFACT_VERSION = "pramagent-rfc3161-artifact-v1"
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ExternalAnchorError(RuntimeError):
    """Raised when an external witness cannot be reached or verified."""


def _require_anchor_dependencies() -> None:
    try:
        import cryptography  # noqa: F401
        import requests  # noqa: F401
        import rfc3161_client  # noqa: F401
        import sigstore  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise EvidenceV2DependencyError(
            'external anchors require "pramagent[evidence-anchors]"'
        ) from exc


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ExternalAnchorError(f"{label} is not canonical base64") from exc
    if _b64encode(decoded) != value:
        raise ExternalAnchorError(f"{label} is not canonical base64")
    return decoded


def _checkpoint_payload(checkpoint_hash: str, domain: bytes) -> bytes:
    if len(checkpoint_hash) != 64:
        raise EvidenceV2Error("checkpoint hash must be SHA-256 hex")
    try:
        digest = bytes.fromhex(checkpoint_hash)
    except ValueError as exc:
        raise EvidenceV2Error("checkpoint hash must be SHA-256 hex") from exc
    return domain + digest


def _datetime_to_us(value: datetime) -> int:
    if value.tzinfo is None:
        raise ExternalAnchorError("witness time has no timezone")
    normalized = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = normalized - epoch
    return (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def _read_limited_response(response: Any, maximum: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise ExternalAnchorError("external witness response is too large")
        except ValueError as exc:
            raise ExternalAnchorError("invalid witness Content-Length") from exc
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > maximum:
            raise ExternalAnchorError("external witness response is too large")
        chunks.append(chunk)
    return b"".join(chunks)


class SigstoreAnchorProvider:
    """Issue and verify Sigstore TSA and Rekor anchors.

    Sigstore's top-level verifier requires a Fulcio identity. Pramagent signs
    checkpoints with its own hybrid keys, so this adapter uses a disposable
    P-256 certificate only to satisfy Rekor's hashedrekord format. Checkpoint
    identity continues to come from the independently verified hybrid
    signatures; the Rekor entry establishes publication, not authorship.
    """

    def __init__(
        self,
        trust_config: Any,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        _require_anchor_dependencies()
        if timeout_seconds <= 0 or max_response_bytes <= 0:
            raise ValueError("anchor client limits must be positive")
        self._trust_config = trust_config
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    @classmethod
    def production(
        cls,
        *,
        offline: bool = False,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> "SigstoreAnchorProvider":
        """Load Sigstore production trust material through its TUF client."""
        _require_anchor_dependencies()
        from sigstore.models import ClientTrustConfig

        return cls(
            ClientTrustConfig.production(offline=offline),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    @property
    def tsa_url(self) -> str:
        clients = self._trust_config.signing_config.get_tsas()
        if not clients:
            raise ExternalAnchorError("Sigstore trust config has no active TSA")
        return clients[0].url

    @property
    def transparency_url(self) -> str:
        clients = self._trust_config.signing_config.get_tlogs()
        if not clients:
            raise ExternalAnchorError(
                "Sigstore trust config has no active transparency log"
            )
        return clients[0].url

    def issue_rfc3161(self, checkpoint: SignedCheckpointV2) -> ExternalAnchorV2:
        """Timestamp a signed checkpoint and verify the response before use."""
        checkpoint.validate()
        payload = _checkpoint_payload(
            checkpoint.checkpoint_hash, RFC3161_ANCHOR_DOMAIN
        )
        return self._issue_rfc3161_payload(
            payload, reference_hash=checkpoint.checkpoint_hash
        )

    def issue_archive_timestamp(self, payload: bytes) -> ExternalAnchorV2:
        """Timestamp RFC 4998 renewal material outside checkpoint semantics."""
        if not payload:
            raise ExternalAnchorError("archive timestamp payload cannot be empty")
        return self._issue_rfc3161_payload(
            payload, reference_hash=hashlib.sha256(payload).hexdigest()
        )

    def _issue_rfc3161_payload(
        self, payload: bytes, *, reference_hash: str
    ) -> ExternalAnchorV2:
        from requests import Session
        from requests.exceptions import RequestException
        from rfc3161_client import (
            HashAlgorithm,
            TimestampRequestBuilder,
            decode_timestamp_response,
        )

        request = (
            TimestampRequestBuilder()
            .hash_algorithm(HashAlgorithm.SHA256)
            .data(payload)
            .nonce(nonce=True)
            .build()
        )
        session = Session()
        session.headers.update(
            {
                "Accept": "application/timestamp-reply",
                "Content-Type": "application/timestamp-query",
                "User-Agent": "pramagent-evidence-anchor/2",
            }
        )
        try:
            response = session.post(
                self.tsa_url,
                data=request.as_bytes(),
                timeout=self.timeout_seconds,
                stream=True,
            )
            response.raise_for_status()
            encoded_response = _read_limited_response(
                response, self.max_response_bytes
            )
        except RequestException as exc:
            raise ExternalAnchorError(f"RFC 3161 request failed: {exc}") from exc
        finally:
            session.close()
        try:
            timestamp = decode_timestamp_response(encoded_response)
        except ValueError as exc:
            raise ExternalAnchorError("TSA returned an invalid response") from exc
        self._verify_timestamp(
            timestamp,
            payload=payload,
            nonce=request.nonce,
        )
        issued_at_us = _datetime_to_us(timestamp.tst_info.gen_time)
        artifact = canonicalize_jcs(
            {
                "artifact_version": RFC3161_ARTIFACT_VERSION,
                "nonce_decimal": str(request.nonce),
                "request_b64": _b64encode(request.as_bytes()),
                "response_b64": _b64encode(encoded_response),
            }
        )
        certificates = set(timestamp.signed_data.certificates)
        certificates.update(self._tsa_trust_certificates())
        certificate_chain = tuple(
            _b64encode(item) for item in sorted(certificates)
        )
        from .revocation import capture_revocation_evidence

        revocation_material = capture_revocation_evidence(
            certificate_chain,
            timeout_seconds=self.timeout_seconds,
            max_response_bytes=self.max_response_bytes,
        )
        return ExternalAnchorV2(
            anchor_type="RFC3161",
            witness_id=self.tsa_url,
            checkpoint_hash=reference_hash,
            issued_at_us=issued_at_us,
            artifact_b64=_b64encode(artifact),
            certificate_chain_b64=certificate_chain,
            revocation_material_b64=revocation_material,
            anchor_id=hashlib.sha256(encoded_response).hexdigest(),
        )

    def verify_rfc3161(self, anchor: ExternalAnchorV2) -> bool:
        """Verify an RFC 3161 artifact against TUF-authenticated TSA roots."""
        payload = _checkpoint_payload(
            anchor.checkpoint_hash, RFC3161_ANCHOR_DOMAIN
        )
        return self._verify_rfc3161_payload(anchor, payload)

    def verify_archive_timestamp(
        self, anchor: ExternalAnchorV2, payload: bytes
    ) -> bool:
        """Verify an archive timestamp and its payload-reference digest."""
        if anchor.checkpoint_hash != hashlib.sha256(payload).hexdigest():
            return False
        return self._verify_rfc3161_payload(anchor, payload)

    def _verify_rfc3161_payload(
        self, anchor: ExternalAnchorV2, payload: bytes
    ) -> bool:
        anchor.validate()
        if anchor.anchor_type != "RFC3161" or anchor.witness_id != self.tsa_url:
            return False
        from rfc3161_client import decode_timestamp_response

        try:
            artifact = json.loads(
                _b64decode(anchor.artifact_b64, "RFC 3161 artifact")
            )
            if set(artifact) != {
                "artifact_version",
                "nonce_decimal",
                "request_b64",
                "response_b64",
            }:
                return False
            if artifact["artifact_version"] != RFC3161_ARTIFACT_VERSION:
                return False
            nonce = int(artifact["nonce_decimal"])
            if nonce < 0:
                return False
            encoded_response = _b64decode(
                artifact["response_b64"], "RFC 3161 response"
            )
            timestamp = decode_timestamp_response(encoded_response)
            self._verify_timestamp(timestamp, payload=payload, nonce=nonce)
            if _datetime_to_us(timestamp.tst_info.gen_time) != anchor.issued_at_us:
                return False
            if hashlib.sha256(encoded_response).hexdigest() != anchor.anchor_id:
                return False
            request_bytes = _b64decode(
                artifact["request_b64"], "RFC 3161 request"
            )
            if not request_bytes:
                return False
            expected_certs = set(timestamp.signed_data.certificates)
            stored_certs = {
                _b64decode(item, "RFC 3161 certificate")
                for item in anchor.certificate_chain_b64
            }
            return expected_certs.issubset(stored_certs)
        except (ExternalAnchorError, ValueError, TypeError, KeyError):
            return False

    def _tsa_trust_certificates(self) -> tuple[bytes, ...]:
        from cryptography.hazmat.primitives import serialization

        result: list[bytes] = []
        for authority in self._trust_config.trusted_root.get_timestamp_authorities():
            for certificate in authority.certificates(allow_expired=True):
                result.append(
                    certificate.public_bytes(serialization.Encoding.DER)
                )
        if not result:
            raise ExternalAnchorError("Sigstore trust root has no TSA certificates")
        return tuple(result)

    def _verify_timestamp(self, timestamp: Any, *, payload: bytes, nonce: int) -> None:
        from rfc3161_client import VerifierBuilder

        authorities = self._trust_config.trusted_root.get_timestamp_authorities()
        for authority in authorities:
            chain = authority.certificates(allow_expired=True)
            if not chain:
                continue
            builder = VerifierBuilder(nonce=nonce)
            for intermediate in chain[:-1]:
                builder = builder.add_intermediate_certificate(intermediate)
            builder = builder.add_root_certificate(chain[-1])
            try:
                verified = builder.build().verify_message(timestamp, payload)
            except Exception:
                verified = False
            if verified:
                return
        raise ExternalAnchorError("RFC 3161 response failed trust verification")

    def publish_transparency(
        self, checkpoint: SignedCheckpointV2
    ) -> ExternalAnchorV2:
        """Publish the checkpoint digest and return a verified Rekor receipt."""
        checkpoint.validate()
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from cryptography.x509.oid import NameOID
        from sigstore.hashes import Hashed
        from sigstore.models import Bundle, KeyringPurpose
        from sigstore_models.common.v1 import HashAlgorithm

        payload = _checkpoint_payload(
            checkpoint.checkpoint_hash, TRANSPARENCY_ANCHOR_DOMAIN
        )
        digest = hashlib.sha256(payload).digest()
        private_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Pramagent checkpoint publication")]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        signature = private_key.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        client = self._trust_config.signing_config.get_tlogs()[0]
        self._configure_rekor_session(client)
        try:
            # This compatibility seam is isolated because Sigstore's public
            # signing API assumes a Fulcio-issued workload identity.
            proposed = client._build_hashed_rekord_request(
                Hashed(algorithm=HashAlgorithm.SHA2_256, digest=digest),
                signature,
                certificate,
            )
            entry = client.create_entry(proposed)
            entry._verify(
                self._trust_config.trusted_root.rekor_keyring(
                    KeyringPurpose.VERIFY
                )
            )
        except Exception as exc:
            raise ExternalAnchorError(f"transparency publication failed: {exc}") from exc
        integrated_time = entry._inner.integrated_time
        if integrated_time is None:
            raise ExternalAnchorError(
                "transparency receipt has no independently signed integration time"
            )
        bundle = Bundle.from_parts(certificate, signature, entry).to_json().encode(
            "utf-8"
        )
        anchor_id = f"{entry._inner.log_id.key_id.hex()}:{entry._inner.log_index}"
        anchor = ExternalAnchorV2(
            anchor_type="transparency-log",
            witness_id=self.transparency_url,
            checkpoint_hash=checkpoint.checkpoint_hash,
            issued_at_us=int(integrated_time) * 1_000_000,
            artifact_b64=_b64encode(bundle),
            certificate_chain_b64=(
                _b64encode(
                    certificate.public_bytes(serialization.Encoding.DER)
                ),
            ),
            anchor_id=anchor_id,
        )
        if not self.verify_transparency(anchor):
            raise ExternalAnchorError(
                "transparency receipt did not bind the requested checkpoint"
            )
        return anchor

    def _configure_rekor_session(self, client: Any) -> None:
        """Apply bounded network behavior to Sigstore's Rekor adapter."""
        import requests

        timeout = self.timeout_seconds
        maximum = self.max_response_bytes

        class BoundedSession(requests.Session):
            def request(self, method: str, url: str, **kwargs: Any) -> Any:
                kwargs.setdefault("timeout", timeout)
                response = super().request(method, url, **kwargs)
                declared = response.headers.get("Content-Length")
                if declared:
                    try:
                        if int(declared) > maximum:
                            response.close()
                            raise ExternalAnchorError(
                                "transparency response is too large"
                            )
                    except ValueError as exc:
                        response.close()
                        raise ExternalAnchorError(
                            "invalid transparency Content-Length"
                        ) from exc
                if len(response.content) > maximum:
                    response.close()
                    raise ExternalAnchorError(
                        "transparency response is too large"
                    )
                return response

        session = BoundedSession()
        session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "pramagent-evidence-anchor/2",
            }
        )
        client._thread_local.session = session

    def verify_transparency(self, anchor: ExternalAnchorV2) -> bool:
        """Verify Rekor inclusion, checkpoint signature, and artifact binding."""
        anchor.validate()
        if (
            anchor.anchor_type != "transparency-log"
            or anchor.witness_id != self.transparency_url
        ):
            return False
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from sigstore.models import Bundle, KeyringPurpose

        try:
            bundle = Bundle.from_json(
                _b64decode(anchor.artifact_b64, "transparency bundle")
            )
            entry = bundle.log_entry
            entry._verify(
                self._trust_config.trusted_root.rekor_keyring(
                    KeyringPurpose.VERIFY
                )
            )
            integrated_time = entry._inner.integrated_time
            if integrated_time is None:
                return False
            if int(integrated_time) * 1_000_000 != anchor.issued_at_us:
                return False
            expected_id = (
                f"{entry._inner.log_id.key_id.hex()}:{entry._inner.log_index}"
            )
            if expected_id != anchor.anchor_id:
                return False
            payload = _checkpoint_payload(
                anchor.checkpoint_hash, TRANSPARENCY_ANCHOR_DOMAIN
            )
            digest = hashlib.sha256(payload).digest()
            public_key = bundle.signing_certificate.public_key()
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            public_key.verify(
                bundle.signature,
                digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
            if not self._rekor_body_matches(
                entry._inner.canonicalized_body,
                digest=digest,
                signature=bundle.signature,
                certificate_pem=bundle.signing_certificate.public_bytes(
                    serialization.Encoding.PEM
                ),
            ):
                return False
            stored_certs = tuple(
                _b64decode(item, "transparency certificate")
                for item in anchor.certificate_chain_b64
            )
            cert_der = bundle.signing_certificate.public_bytes(
                serialization.Encoding.DER
            )
            return stored_certs == (cert_der,)
        except Exception:
            return False

    @staticmethod
    def _rekor_body_matches(
        encoded: bytes,
        *,
        digest: bytes,
        signature: bytes,
        certificate_pem: bytes,
    ) -> bool:
        """Check the v1 hashedrekord body bound by the inclusion proof."""
        try:
            body = json.loads(encoded)
            spec = body["spec"]
            digest_record = spec["data"]["hash"]
            signature_record = spec["signature"]
            return (
                body["kind"] == "hashedrekord"
                and digest_record["algorithm"] == "sha256"
                and digest_record["value"] == digest.hex()
                and _b64decode(signature_record["content"], "Rekor signature")
                == signature
                and _b64decode(
                    signature_record["publicKey"]["content"],
                    "Rekor certificate",
                )
                == certificate_pem
            )
        except (KeyError, TypeError, ValueError, ExternalAnchorError):
            return False

    def issue_all(
        self, checkpoint: SignedCheckpointV2
    ) -> tuple[ExternalAnchorV2, ExternalAnchorV2]:
        """Issue both policy-required anchors in deterministic order."""
        return (
            self.issue_rfc3161(checkpoint),
            self.publish_transparency(checkpoint),
        )

    def verifiers(self) -> Mapping[str, Any]:
        return {
            "RFC3161": self.verify_rfc3161,
            "transparency-log": self.verify_transparency,
        }


def attach_anchors(
    envelope: EvidenceEnvelopeV2,
    anchors: tuple[ExternalAnchorV2, ...] | list[ExternalAnchorV2],
) -> EvidenceEnvelopeV2:
    """Return an envelope with anchors for its exact signed checkpoint."""
    for anchor in anchors:
        anchor.validate()
        if anchor.checkpoint_hash != envelope.checkpoint.checkpoint_hash:
            raise EvidenceV2Error("cannot attach an anchor for another checkpoint")
    by_type = {anchor.anchor_type: anchor for anchor in envelope.anchors}
    for anchor in anchors:
        by_type[anchor.anchor_type] = anchor
    return replace(
        envelope,
        anchors=tuple(by_type[key] for key in sorted(by_type)),
    )


@dataclass(frozen=True)
class AnchorJob:
    checkpoint_hash: str
    status: str
    attempts: int
    next_attempt_at_us: int
    last_error: str
    anchors: tuple[ExternalAnchorV2, ...]


@runtime_checkable
class AnchorOutboxBackend(Protocol):
    """Storage contract shared by local and distributed anchor workers."""

    def close(self) -> None: ...

    def enqueue(
        self, checkpoint: SignedCheckpointV2, *, now_us: int | None = None
    ) -> None: ...

    def process_one(
        self,
        provider: SigstoreAnchorProvider,
        *,
        now_us: int | None = None,
        lease_seconds: int = 60,
    ) -> AnchorJob | None: ...

    def get(self, checkpoint_hash: str) -> AnchorJob | None: ...


class SQLiteAnchorOutbox:
    """Durable retry queue for off-path external anchoring."""

    def __init__(self, path: str | Path) -> None:
        resolved = Path(path).expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.path = resolved
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(resolved), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_anchor_jobs (
                    checkpoint_hash TEXT PRIMARY KEY,
                    checkpoint_json TEXT NOT NULL,
                    anchors_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at_us INTEGER NOT NULL,
                    locked_until_us INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    updated_at_us INTEGER NOT NULL
                )
                """
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteAnchorOutbox":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def enqueue(
        self, checkpoint: SignedCheckpointV2, *, now_us: int | None = None
    ) -> None:
        checkpoint.validate()
        current = now_us if now_us is not None else time.time_ns() // 1_000
        encoded = canonicalize_jcs(checkpoint.to_dict()).decode("utf-8")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO evidence_anchor_jobs (
                    checkpoint_hash, checkpoint_json, status,
                    next_attempt_at_us, updated_at_us
                ) VALUES (?, ?, 'queued', ?, ?)
                ON CONFLICT(checkpoint_hash) DO NOTHING
                """,
                (checkpoint.checkpoint_hash, encoded, current, current),
            )

    def process_one(
        self,
        provider: SigstoreAnchorProvider,
        *,
        now_us: int | None = None,
        lease_seconds: int = 60,
    ) -> AnchorJob | None:
        """Process one due checkpoint, retaining successful partial anchors."""
        current = now_us if now_us is not None else time.time_ns() // 1_000
        row = self._claim(current, lease_seconds)
        if row is None:
            return None
        checkpoint = SignedCheckpointV2.from_dict(json.loads(row["checkpoint_json"]))
        anchors = {
            item.anchor_type: item
            for item in (
                ExternalAnchorV2.from_dict(raw)
                for raw in json.loads(row["anchors_json"])
            )
        }
        try:
            if "RFC3161" not in anchors:
                anchors["RFC3161"] = provider.issue_rfc3161(checkpoint)
                self._save_progress(checkpoint.checkpoint_hash, anchors, current)
            if "transparency-log" not in anchors:
                anchors["transparency-log"] = provider.publish_transparency(
                    checkpoint
                )
                self._save_progress(checkpoint.checkpoint_hash, anchors, current)
        except Exception as exc:
            attempts = int(row["attempts"]) + 1
            delay_seconds = min(3600, 2 ** min(attempts, 11))
            self._finish(
                checkpoint.checkpoint_hash,
                status="retry",
                attempts=attempts,
                next_attempt_at_us=current + delay_seconds * 1_000_000,
                last_error=str(exc),
                anchors=anchors,
                now_us=current,
            )
            return self.get(checkpoint.checkpoint_hash)
        self._finish(
            checkpoint.checkpoint_hash,
            status="complete",
            attempts=int(row["attempts"]) + 1,
            next_attempt_at_us=current,
            last_error="",
            anchors=anchors,
            now_us=current,
        )
        return self.get(checkpoint.checkpoint_hash)

    def get(self, checkpoint_hash: str) -> AnchorJob | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM evidence_anchor_jobs WHERE checkpoint_hash = ?",
                (checkpoint_hash,),
            ).fetchone()
        if row is None:
            return None
        return AnchorJob(
            checkpoint_hash=row["checkpoint_hash"],
            status=row["status"],
            attempts=int(row["attempts"]),
            next_attempt_at_us=int(row["next_attempt_at_us"]),
            last_error=row["last_error"],
            anchors=tuple(
                ExternalAnchorV2.from_dict(item)
                for item in json.loads(row["anchors_json"])
            ),
        )

    def _claim(self, now_us: int, lease_seconds: int) -> sqlite3.Row | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    """
                    SELECT * FROM evidence_anchor_jobs
                    WHERE status IN ('queued', 'retry', 'running')
                      AND next_attempt_at_us <= ?
                      AND (status != 'running' OR locked_until_us <= ?)
                    ORDER BY next_attempt_at_us, checkpoint_hash
                    LIMIT 1
                    """,
                    (now_us, now_us),
                ).fetchone()
                if row is not None:
                    self._conn.execute(
                        """
                        UPDATE evidence_anchor_jobs
                        SET status = 'running', locked_until_us = ?, updated_at_us = ?
                        WHERE checkpoint_hash = ?
                        """,
                        (
                            now_us + lease_seconds * 1_000_000,
                            now_us,
                            row["checkpoint_hash"],
                        ),
                    )
                self._conn.commit()
                return row
            except Exception:
                self._conn.rollback()
                raise

    def _save_progress(
        self,
        checkpoint_hash: str,
        anchors: Mapping[str, ExternalAnchorV2],
        now_us: int,
    ) -> None:
        encoded = canonicalize_jcs(
            [anchors[key].to_dict() for key in sorted(anchors)]
        ).decode("utf-8")
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE evidence_anchor_jobs
                SET anchors_json = ?, updated_at_us = ?
                WHERE checkpoint_hash = ?
                """,
                (encoded, now_us, checkpoint_hash),
            )

    def _finish(
        self,
        checkpoint_hash: str,
        *,
        status: str,
        attempts: int,
        next_attempt_at_us: int,
        last_error: str,
        anchors: Mapping[str, ExternalAnchorV2],
        now_us: int,
    ) -> None:
        encoded = canonicalize_jcs(
            [anchors[key].to_dict() for key in sorted(anchors)]
        ).decode("utf-8")
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE evidence_anchor_jobs
                SET anchors_json = ?, status = ?, attempts = ?,
                    next_attempt_at_us = ?, locked_until_us = 0,
                    last_error = ?, updated_at_us = ?
                WHERE checkpoint_hash = ?
                """,
                (
                    encoded,
                    status,
                    attempts,
                    next_attempt_at_us,
                    last_error[:2000],
                    now_us,
                    checkpoint_hash,
                ),
            )


__all__ = [
    "AnchorJob",
    "AnchorOutboxBackend",
    "ExternalAnchorError",
    "RFC3161_ANCHOR_DOMAIN",
    "SQLiteAnchorOutbox",
    "SigstoreAnchorProvider",
    "TRANSPARENCY_ANCHOR_DOMAIN",
    "attach_anchors",
]
