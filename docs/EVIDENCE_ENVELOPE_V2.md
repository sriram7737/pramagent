# Evidence Envelope V2

Status: implementation specification, version 2.0.

This document defines Pramagent's portable evidence envelope. Version 2 is
additive: readers continue to accept existing version 1 quantum evidence, and
version 1 hashing bytes are never rewritten.

The protocol authenticates what Pramagent checkpointed and when an independent
witness observed the checkpoint. It does not prove that an upstream provider,
model, operator, or QPU reported a truthful underlying event.

## Encoding profile

All signed structures MUST be canonicalized with RFC 8785 JCS. Pramagent adds
these constraints:

- Floating-point numbers MUST NOT appear in a V2 signed structure.
- Time values use integer microseconds since the Unix epoch and end in `_us`.
- Currency values use explicitly named integer minor units, such as
  `cost_microusd`. Unknown cost remains `null`; it is not encoded as zero.
- Integers MUST be within `[-9007199254740991, 9007199254740991]`.
- JSON object keys MUST be strings and invalid Unicode MUST be rejected.
- Binary values use canonical padded base64.

These rules avoid cross-language number serialization differences while JCS
provides the required Unicode escaping and UTF-16 property ordering. Python's
`json.dumps(sort_keys=True)` is not a substitute for JCS.

## Leaf

An `EvidenceLeafV2` contains a record identifier, sequence, record version,
SHA-256 record digest, observation time, provenance mode, source assurance,
and a persisted random nonce of at least 128 bits. Its hash is:

```text
SHA-256(0x00 || JCS(leaf-without-leaf_hash))
```

The nonce MUST be stored with the leaf. Losing it makes the leaf and future
inclusion proofs impossible to regenerate. It also prevents inexpensive
dictionary recovery of low-entropy record digests from a published tree.

`native-v2` records carry their integer-only record in the envelope and the
verifier recomputes its digest. `legacy-v1-wrap` leaves carry the already-issued
V1 digest. Wrapping does not retroactively authenticate V1 creation.

## Merkle epoch

Leaves are combined with the domain-separated tree rules used by the
Certificate Transparency family:

```text
leaf = SHA-256(0x00 || JCS(leaf material))
node = SHA-256(0x01 || left || right)
```

The tree supports inclusion proofs and append-only consistency proofs. A
consistency proof only protects a party that knows an earlier checkpoint. A
deployment MUST therefore publish or cross-sign checkpoints with an
independent witness; a private log can otherwise present internally consistent
split views.

## Checkpoint and signature policy

The signed checkpoint includes:

- schema and domain identifiers;
- epoch ID, tree size, and first/last sequence;
- Merkle root and previous signed-checkpoint hash;
- issuance time in integer microseconds;
- hash, Merkle, and canonicalization algorithm identifiers;
- signature-policy version and exact required algorithm set; and
- external-witness policy version.

Signature input is the ASCII domain prefix
`pramagent:evidence-checkpoint:v2`, one zero byte, and the JCS checkpoint.

Policy `pramagent-hybrid-2026-01` requires exactly one Ed25519 signature and
exactly one ML-DSA-65 signature. Both MUST verify. Missing, duplicate, unknown,
or extra signatures fail verification. The verifier MUST obtain the complete
policy from a trusted local registry and compare it with the signed policy ID
and algorithm set. This prevents both signature stripping and substitution of
an attacker-defined weaker policy while allowing a future policy version to
rotate algorithms.

Implementations using ML-DSA are not automatically FIPS-validated merely
because the algorithm is standardized. Deployment validation depends on the
cryptographic module and operating environment.

## External witnesses and long-term validation

An RFC 3161 TSA token is the primary time assertion. A transparency-log or
customer cross-signing receipt supplies externally observable checkpoint
publication. Pramagent reaches `tsa_anchored` only when both artifacts verify;
a TSA token without publication is reported with a warning.

The optional `pramagent[evidence-anchors]` integration uses Sigstore's
TUF-authenticated production trust configuration. It timestamps the
domain-separated signed-checkpoint hash through Sigstore's RFC 3161 service,
then publishes a separately domain-separated digest as a Rekor `hashedrekord`.
The Rekor certificate is disposable and establishes no workload identity;
Pramagent authorship remains established by the trusted hybrid checkpoint
keys. Verification checks the timestamp imprint and nonce, the TSA chain, the
logged artifact signature, Rekor inclusion proof, and signed log checkpoint.

The two default artifacts are separate witness mechanisms, but both currently
belong to the Sigstore service ecosystem. Deployments requiring organizational
independence should add a separately operated TSA, publication witness, or
customer cross-signature and issue a new anchor-policy version.

The complete timestamp token, certificate chain, and contemporaneous
revocation material MUST be retained. Seven-year retention also requires an
archive-renewal procedure before certificates or algorithms expire. RFC 4998
Evidence Record Syntax or an equivalent archive-timestamp profile should be
selected by deployment policy. V2 models external artifacts but deliberately
delegates their cryptographic validation to a configured TSA/log verifier; it
does not treat an operator-supplied timestamp field as trusted time.

The current Sigstore adapter retains the complete RFC 3161 request, response,
embedded signer certificate, TUF-provided certificate chain, and complete
Rekor bundle. It does not yet fetch contemporaneous OCSP/CRL material and does
not implement RFC 4998 renewal. Therefore `tsa_anchored` describes successful
verification under current trust material, not a seven-year long-term
validation guarantee.

## Operations

External calls are kept off the protected request path. `SQLiteAnchorOutbox`
stores the signed checkpoint, completed anchors, attempt count, next retry
time, and bounded error text. It uses a lease to recover interrupted workers,
retains a successful TSA token if Rekor fails, and retries with exponential
backoff capped at one hour. Operators needing multiple anchor workers should
replace this single-host SQLite queue with their shared database or queue.

```bash
pip install "pramagent[evidence-anchors]"

pramagent evidence-v2-anchor \
  --envelope evidence.json \
  --output evidence.anchored.json

pramagent evidence-v2-verify \
  --envelope evidence.anchored.json \
  --keys verification-keys.json \
  --anchor-trust sigstore-offline \
  --require-assurance tsa_anchored
```

`sigstore-production` refreshes trust metadata through TUF before verification.
`sigstore-offline` uses packaged or previously cached trust material and makes
no trust-metadata network request. A stale cache can fail closed after service
key rotation; online refresh should happen in the anchoring worker.

## Assurance output

Every verification report MUST include all three fields:

- `record_assurance`: assurance inherited from the source record.
- `checkpoint_assurance`: assurance established by inclusion, signatures, and
  external witnesses.
- `assurance_level`: the assurance callers may rely on for the record's claimed
  origin.

The ordered values are `checksum_only`, `hmac_authenticated`,
`asymmetric_checkpointed`, and `tsa_anchored`. A legacy V1 wrapper remains at
its source assurance even when its later checkpoint is signed and anchored;
the report separately exposes the stronger checkpoint-time evidence.

## Key operations

Private signing keys MUST live outside evidence records and application logs.
Production deployments should isolate them in a KMS, HSM, or signing service.
Trusted public keys and policy versions require their own authenticated
registry, rotation procedure, revocation procedure, and disaster-recovery
backup. Post-quantum signatures do not protect a deployment whose signing keys
are controlled by the same compromised operator rewriting the evidence.

## Golden vectors

`pramagent/quantum/data/evidence_envelope_v2_golden.json` is normative for this
implementation. It fixes JCS bytes, leaf hashes, Merkle roots, inclusion and
consistency proofs, public keys, signatures, and a complete native V2 envelope.
Cross-language implementations should verify this fixture before accepting
production evidence.

References: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html),
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html),
[RFC 4998](https://www.rfc-editor.org/rfc/rfc4998.html),
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html), and
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
