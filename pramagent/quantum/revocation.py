"""Capture and validate certificate-status evidence for long-term archives."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .evidence_v2 import canonicalize_jcs

REVOCATION_ARTIFACT_VERSION = "pramagent-revocation-evidence-v1"


class RevocationEvidenceError(RuntimeError):
    """Raised when advertised certificate-status evidence cannot be trusted."""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _to_us(value: datetime | None) -> int:
    if value is None:
        return 0
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - epoch
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


@dataclass(frozen=True)
class RevocationEvidence:
    evidence_type: str
    certificate_sha256: str
    issuer_sha256: str
    captured_at_us: int
    status: str
    source_url: str = ""
    this_update_us: int = 0
    next_update_us: int = 0
    response_b64: str = ""
    response_sha256: str = ""
    artifact_version: str = REVOCATION_ARTIFACT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_version": self.artifact_version,
            "captured_at_us": self.captured_at_us,
            "certificate_sha256": self.certificate_sha256,
            "evidence_type": self.evidence_type,
            "issuer_sha256": self.issuer_sha256,
            "next_update_us": self.next_update_us,
            "response_b64": self.response_b64,
            "response_sha256": self.response_sha256,
            "source_url": self.source_url,
            "status": self.status,
            "this_update_us": self.this_update_us,
        }

    def encode(self) -> str:
        return _b64(canonicalize_jcs(self.to_dict()))


def _public_endpoint(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RevocationEvidenceError("revocation endpoint must use HTTP(S)")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        }
    except OSError as exc:
        raise RevocationEvidenceError("revocation endpoint cannot be resolved") from exc
    for address in addresses:
        value = ipaddress.ip_address(address)
        if not value.is_global:
            raise RevocationEvidenceError(
                "revocation endpoint resolves to a non-public address"
            )


def _response_bytes(response: Any, maximum: int) -> bytes:
    response.raise_for_status()
    content = bytes(response.content)
    if not content or len(content) > maximum:
        raise RevocationEvidenceError("revocation response has invalid size")
    return content


def _verify_signature(public_key: Any, signature: bytes, data: bytes, algorithm: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(algorithm))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
    else:
        raise RevocationEvidenceError("unsupported revocation signer key type")


def _issuer_for(certificate: Any, certificates: list[Any]) -> Any | None:
    return next(
        (candidate for candidate in certificates if candidate.subject == certificate.issuer),
        None,
    )


def _ocsp_urls(certificate: Any) -> list[str]:
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

    try:
        access = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    return [
        item.access_location.value
        for item in access
        if item.access_method == AuthorityInformationAccessOID.OCSP
        and isinstance(item.access_location, x509.UniformResourceIdentifier)
    ]


def _crl_urls(certificate: Any) -> list[str]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        points = certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []
    urls: list[str] = []
    for point in points:
        if point.full_name:
            urls.extend(
                name.value
                for name in point.full_name
                if isinstance(name, x509.UniformResourceIdentifier)
            )
    return urls


def _capture_ocsp(
    certificate: Any,
    issuer: Any,
    url: str,
    *,
    session: Any,
    captured_at_us: int,
    timeout_seconds: int,
    max_response_bytes: int,
) -> RevocationEvidence:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp

    _public_endpoint(url)
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(certificate, issuer, hashes.SHA256())
        .build()
    )
    response = session.post(
        url,
        data=request.public_bytes(serialization.Encoding.DER),
        headers={
            "Accept": "application/ocsp-response",
            "Content-Type": "application/ocsp-request",
        },
        timeout=timeout_seconds,
        allow_redirects=False,
    )
    encoded = _response_bytes(response, max_response_bytes)
    parsed = ocsp.load_der_ocsp_response(encoded)
    if parsed.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise RevocationEvidenceError("OCSP responder did not return success")
    if parsed.serial_number != certificate.serial_number:
        raise RevocationEvidenceError("OCSP response is for another certificate")
    signer = issuer
    if parsed.responder_name is not None and parsed.responder_name != issuer.subject:
        signer = next(
            (item for item in parsed.certificates if item.subject == parsed.responder_name),
            None,
        )
        if signer is None:
            raise RevocationEvidenceError("OCSP responder certificate is missing")
        _verify_signature(
            issuer.public_key(), signer.signature, signer.tbs_certificate_bytes,
            signer.signature_hash_algorithm,
        )
    _verify_signature(
        signer.public_key(), parsed.signature, parsed.tbs_response_bytes,
        parsed.signature_hash_algorithm,
    )
    status = parsed.certificate_status.name.lower()
    if status != "good":
        raise RevocationEvidenceError(f"OCSP certificate status is {status}")
    return RevocationEvidence(
        evidence_type="OCSP",
        certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        issuer_sha256=issuer.fingerprint(hashes.SHA256()).hex(),
        captured_at_us=captured_at_us,
        status=status,
        source_url=url,
        this_update_us=_to_us(parsed.this_update_utc),
        next_update_us=_to_us(parsed.next_update_utc),
        response_b64=_b64(encoded),
        response_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _capture_crl(
    certificate: Any,
    issuer: Any,
    url: str,
    *,
    session: Any,
    captured_at_us: int,
    timeout_seconds: int,
    max_response_bytes: int,
) -> RevocationEvidence:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    _public_endpoint(url)
    response = session.get(
        url, timeout=timeout_seconds, allow_redirects=False
    )
    encoded = _response_bytes(response, max_response_bytes)
    try:
        crl = x509.load_der_x509_crl(encoded)
    except ValueError:
        crl = x509.load_pem_x509_crl(encoded)
    if crl.issuer != issuer.subject:
        raise RevocationEvidenceError("CRL issuer does not match certificate issuer")
    _verify_signature(
        issuer.public_key(), crl.signature, crl.tbs_certlist_bytes,
        crl.signature_hash_algorithm,
    )
    if crl.get_revoked_certificate_by_serial_number(certificate.serial_number):
        raise RevocationEvidenceError("certificate is revoked by captured CRL")
    return RevocationEvidence(
        evidence_type="CRL",
        certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        issuer_sha256=issuer.fingerprint(hashes.SHA256()).hex(),
        captured_at_us=captured_at_us,
        status="good",
        source_url=url,
        this_update_us=_to_us(crl.last_update_utc),
        next_update_us=_to_us(crl.next_update_utc),
        response_b64=_b64(encoded),
        response_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def capture_revocation_evidence(
    certificate_chain_b64: tuple[str, ...] | list[str],
    *,
    session: Any | None = None,
    captured_at_us: int | None = None,
    timeout_seconds: int = 15,
    max_response_bytes: int = 2 * 1024 * 1024,
) -> tuple[str, ...]:
    """Return base64 JCS artifacts for every non-root certificate.

    A certificate with no advertised status service receives an explicit
    `unavailable` artifact. That artifact documents the limitation and is not
    equivalent to a good OCSP or CRL response.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    if not certificate_chain_b64:
        raise RevocationEvidenceError("certificate chain is required")
    certificates = [
        x509.load_der_x509_certificate(base64.b64decode(item, validate=True))
        for item in certificate_chain_b64
    ]
    current = captured_at_us if captured_at_us is not None else time.time_ns() // 1_000
    owns_session = session is None
    if session is None:
        import requests

        session = requests.Session()
    evidence: list[RevocationEvidence] = []
    try:
        for certificate in certificates:
            issuer = _issuer_for(certificate, certificates)
            if issuer is None or issuer == certificate:
                continue
            ocsp_urls = _ocsp_urls(certificate)
            crl_urls = _crl_urls(certificate)
            if not ocsp_urls and not crl_urls:
                evidence.append(
                    RevocationEvidence(
                        evidence_type="unavailable",
                        certificate_sha256=certificate.fingerprint(
                            hashes.SHA256()
                        ).hex(),
                        issuer_sha256=issuer.fingerprint(hashes.SHA256()).hex(),
                        captured_at_us=current,
                        status="no_endpoint_advertised",
                    )
                )
                continue
            for url in ocsp_urls[:1]:
                evidence.append(
                    _capture_ocsp(
                        certificate,
                        issuer,
                        url,
                        session=session,
                        captured_at_us=current,
                        timeout_seconds=timeout_seconds,
                        max_response_bytes=max_response_bytes,
                    )
                )
            for url in crl_urls[:1]:
                evidence.append(
                    _capture_crl(
                        certificate,
                        issuer,
                        url,
                        session=session,
                        captured_at_us=current,
                        timeout_seconds=timeout_seconds,
                        max_response_bytes=max_response_bytes,
                    )
                )
    finally:
        if owns_session:
            session.close()
    return tuple(item.encode() for item in evidence)


__all__ = [
    "REVOCATION_ARTIFACT_VERSION",
    "RevocationEvidence",
    "RevocationEvidenceError",
    "capture_revocation_evidence",
]
