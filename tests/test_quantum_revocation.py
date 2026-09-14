from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("rfc8785")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from pramagent.quantum import RevocationEvidenceError, capture_revocation_evidence


class _Response:
    def __init__(self, content: bytes):
        self.content = content

    def raise_for_status(self):
        pass


class _Session:
    def __init__(self, ocsp_response: bytes, crl: bytes):
        self.ocsp_response = ocsp_response
        self.crl = crl
        self.posts = []
        self.gets = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return _Response(self.ocsp_response)

    def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        return _Response(self.crl)


def _certificate_chain(*, endpoints: bool = True):
    now = datetime.now(timezone.utc)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA CA")])
    issuer = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")]))
        .issuer_name(issuer.subject)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if endpoints:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("https://ocsp.example.com/status"),
                    )
                ]
            ),
            critical=False,
        ).add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "https://crl.example.com/tsa.crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    leaf = builder.sign(issuer_key, hashes.SHA256())
    return issuer_key, issuer, leaf, now


def _status_material(issuer_key, issuer, leaf, now):
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=issuer,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now - timedelta(minutes=1),
            next_update=now + timedelta(days=1),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, issuer)
        .sign(issuer_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=1))
        .sign(issuer_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    return response, crl


def _encoded_chain(leaf, issuer):
    return tuple(
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
        for cert in (leaf, issuer)
    )


def test_capture_validates_and_preserves_ocsp_and_crl(monkeypatch):
    issuer_key, issuer, leaf, now = _certificate_chain()
    response, crl = _status_material(issuer_key, issuer, leaf, now)
    session = _Session(response, crl)
    monkeypatch.setattr(
        "pramagent.quantum.revocation.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    encoded = capture_revocation_evidence(
        _encoded_chain(leaf, issuer),
        session=session,
        captured_at_us=1_789_344_000_000_000,
    )
    material = [json.loads(base64.b64decode(item)) for item in encoded]

    assert [item["evidence_type"] for item in material] == ["OCSP", "CRL"]
    assert all(item["status"] == "good" for item in material)
    assert all(item["response_sha256"] for item in material)
    assert len(session.posts) == 1
    assert len(session.gets) == 1


def test_capture_records_when_certificate_has_no_status_endpoint():
    _, issuer, leaf, _ = _certificate_chain(endpoints=False)

    encoded = capture_revocation_evidence(
        _encoded_chain(leaf, issuer),
        session=_Session(b"unused", b"unused"),
        captured_at_us=1_789_344_000_000_000,
    )
    material = json.loads(base64.b64decode(encoded[0]))

    assert material["evidence_type"] == "unavailable"
    assert material["status"] == "no_endpoint_advertised"
    assert material["response_b64"] == ""


def test_capture_rejects_private_revocation_endpoint(monkeypatch):
    issuer_key, issuer, leaf, now = _certificate_chain()
    response, crl = _status_material(issuer_key, issuer, leaf, now)
    monkeypatch.setattr(
        "pramagent.quantum.revocation.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )

    with pytest.raises(RevocationEvidenceError, match="non-public"):
        capture_revocation_evidence(
            _encoded_chain(leaf, issuer),
            session=_Session(response, crl),
        )


def test_capture_rejects_tampered_ocsp_signature(monkeypatch):
    issuer_key, issuer, leaf, now = _certificate_chain()
    response, crl = _status_material(issuer_key, issuer, leaf, now)
    tampered = response[:-1] + bytes([response[-1] ^ 1])
    monkeypatch.setattr(
        "pramagent.quantum.revocation.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    with pytest.raises(Exception):
        capture_revocation_evidence(
            _encoded_chain(leaf, issuer),
            session=_Session(tampered, crl),
        )
