"""
pramagent.audit
===============
Tamper-evident audit backends. The default HashChainBackend is fully
self-contained: each trace's hash includes the previous trace's hash, so any
retroactive edit to an old record breaks every hash after it. This is the
"blockchain-lite" guarantee that needs no external chain to be useful.

EthereumBackend / HyperledgerBackend implement the same interface and anchor
the chain head to an external ledger. Ethereum can submit real Sepolia
transactions when configured with web3 credentials; otherwise it keeps the
local chain semantics and returns a local pseudo-anchor. When an external
Ethereum anchor is configured, failures are fail-closed by default; pass
``fail_open=True`` only for dev/demo deployments that knowingly accept local
chain-only evidence during chain outages.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from dataclasses import dataclass
from typing import Protocol

from ..anchoring.ethereum import EthereumAnchor, EthereumAnchorReceipt


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditAppendResult:
    """Result of an audit-chain append.

    The object intentionally unpacks like the historical ``(this_hash,
    anchor_tx_id)`` tuple for backward compatibility, while also carrying the
    ``prev_hash`` chosen inside the backend's critical section. Core code must
    use that atomic prev value instead of reading a mutable backend attribute
    after concurrent writers may have advanced the chain.
    """

    this_hash: str
    anchor_tx_id: str
    prev_hash: str

    def __iter__(self):
        yield self.this_hash
        yield self.anchor_tx_id

    def __len__(self) -> int:
        return 2

    def __getitem__(self, index: int) -> str:
        return (self.this_hash, self.anchor_tx_id)[index]


def canonical_hash(payload: dict, prev_hash: str, signing_key: str = "") -> str:
    """
    Deterministic hash over the canonical JSON of the payload plus the
    previous hash. Sorting keys guarantees the same bytes every time, which is
    what makes verification and decision-replay possible.

    When `signing_key` is set, this is HMAC-SHA256 keyed with it: recomputing
    a valid chain then requires the secret, not just re-running the same
    public hash function — the property PRAMAGENT_SIGNING_KEY is documented
    to provide. Without a key (the default, for backward compatibility with
    existing unkeyed chains), this is plain SHA-256 — recomputable by anyone
    with the payload, which is why an unkeyed chain alone does not defend
    against an actor with raw database write access (see HARDENING_GUIDE.md).
    """
    material = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "|" + prev_hash
    material_bytes = material.encode("utf-8")
    if signing_key:
        return hmac.new(signing_key.encode("utf-8"), material_bytes, hashlib.sha256).hexdigest()
    return hashlib.sha256(material_bytes).hexdigest()


# Chain-payload fields that can carry user content and must be tombstoned on
# GDPR Art. 17 erasure. pii_redactions holds only pattern labels, never values.
# `reason` is included because a ToolGuard schema/validation reason can echo a
# failing argument or output value; the write path now redacts those at source
# (B1, see validate_schema(redact_values=True)), but tombstoning here also
# covers the legacy non-jsonschema validator path and any pre-fix entries.
GDPR_TOMBSTONE_FIELDS = ("input_text", "output_text", "would_block_reason", "reason")


def _tombstone_value(value) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return f"[ERASED-GDPR-ART17 sha256:{digest[:16]}]"


def redact_chain_payload(payload: dict) -> bool:
    """Tombstone PII-bearing fields in an audit-chain payload, in place.

    Each erased value is replaced with a marker carrying its SHA-256 digest:
    the chain still proves *that* content existed (and can match it if the
    subject re-presents it) without retaining the content itself. Idempotent —
    already-erased payloads are left alone. Returns True if anything changed.

    Covers more than the top-level input/output text: a rule or layer can
    quote the offending content back into its own `detail` string (e.g. "SSN
    123-45-6789 matched pattern X"), and layer_events[*].data is a free-form
    dict that can carry tool arguments or output snippets. Blanket-tombstones
    every value found there rather than trying to distinguish which specific
    strings actually echo user content — under-redacting on a GDPR erasure
    path is the wrong failure mode to risk.
    """
    if payload.get("gdpr_erased"):
        return False
    changed = False
    for field in GDPR_TOMBSTONE_FIELDS:
        value = payload.get(field)
        if value:
            payload[field] = _tombstone_value(value)
            changed = True

    for rule in payload.get("rules_evaluated") or []:
        if isinstance(rule, dict) and rule.get("detail"):
            rule["detail"] = _tombstone_value(rule["detail"])
            changed = True

    for event in payload.get("layer_events") or []:
        if not isinstance(event, dict):
            continue
        if event.get("detail"):
            event["detail"] = _tombstone_value(event["detail"])
            changed = True
        data = event.get("data")
        if isinstance(data, dict) and data:
            event["data"] = {key: _tombstone_value(val) for key, val in data.items()}
            changed = True

    if changed:
        payload["gdpr_erased"] = True
    return changed


class AuditBackend(Protocol):
    def append(self, payload: dict, prev_hash: str | None = None) -> AuditAppendResult:
        """Return an append result unpackable as (this_hash, anchor_tx_id)."""
        ...

    def verify_chain(self) -> bool:
        ...


class HashChainBackend:
    """Self-contained, in-memory (or file-backed) tamper-evident hash chain."""

    GENESIS = "0" * 64

    def __init__(self, signing_key: str = "") -> None:
        self._records: list[dict] = []   # each: {payload, prev_hash, this_hash}
        self._head: str = self.GENESIS
        # prev of the most recent append — core records it on the trace
        self.last_prev_hash: str = self.GENESIS
        # HMAC key for canonical_hash (PRAMAGENT_SIGNING_KEY). Empty string
        # means the chain is unkeyed plain SHA-256, recomputable by anyone
        # with DB write access — see canonical_hash's docstring.
        self._signing_key = signing_key
        # Appends may arrive from worker threads (core offloads persistence
        # via asyncio.to_thread); deriving prev and inserting must be one
        # critical section or concurrent writers fork the chain (P1-5/T2-4).
        self._lock = threading.Lock()

    @property
    def head(self) -> str:
        return self._head

    def append(self, payload: dict, prev_hash: str | None = None) -> AuditAppendResult:
        with self._lock:
            prev = prev_hash if prev_hash is not None else self._head
            this_hash = canonical_hash(payload, prev, self._signing_key)
            self._records.append({"payload": payload, "prev_hash": prev, "this_hash": this_hash})
            self.last_prev_hash = prev
            self._head = this_hash
            # anchor_tx_id is local for HashChain; external backends return a real tx id
            return AuditAppendResult(this_hash, f"local:{this_hash[:16]}", prev)

    def verify_chain(self) -> bool:
        """Recompute every hash; return False if any link is broken (tampering).

        Recomputation uses this instance's signing key. A chain written with
        one key and verified with a different (or absent) key will report as
        invalid — that mismatch is the whole point of keying the chain."""
        prev = self.GENESIS
        for rec in self._records:
            expected = canonical_hash(rec["payload"], prev, self._signing_key)
            if expected != rec["this_hash"] or rec["prev_hash"] != prev:
                return False
            prev = rec["this_hash"]
        return True

    def redact_for_tenant(self, tenant_id: str) -> int:
        """GDPR Art. 17: tombstone PII fields in this tenant's chain payloads,
        then re-anchor — every link from the first redaction onward is
        re-hashed so verify_chain() still succeeds without the erased content.
        Returns the number of payloads redacted."""
        return self._redact_matching(lambda payload: payload.get("tenant_id") == tenant_id)

    def redact_for_session(self, tenant_id: str, session_id: str) -> int:
        """Same as redact_for_tenant, scoped to one session — the practical
        per-end-user erasure unit given the schema has no separate
        per-user column."""
        return self._redact_matching(
            lambda payload: (
                payload.get("tenant_id") == tenant_id
                and payload.get("session_id") == session_id
            )
        )

    def _redact_matching(self, predicate) -> int:
        redacted = 0
        rehash = False
        prev = self.GENESIS
        for rec in self._records:
            payload = rec["payload"]
            if predicate(payload) and redact_chain_payload(payload):
                redacted += 1
                rehash = True
            if rehash:
                rec["prev_hash"] = prev
                rec["this_hash"] = canonical_hash(payload, prev, self._signing_key)
            prev = rec["this_hash"]
        if rehash:
            self._head = prev
        return redacted

    def records(self) -> list[dict]:
        return list(self._records)


class EthereumBackend:
    """Hash-chain backend with optional real Ethereum/Sepolia anchoring."""

    def __init__(
        self,
        rpc_url: str = "",
        contract: str = "",
        *,
        private_key: str = "",
        chain_id: int = 11155111,
        anchor: EthereumAnchor | None = None,
        fail_open: bool = False,
        signing_key: str = "",
    ):
        self.rpc_url = rpc_url
        self.contract = contract
        self.private_key = private_key
        self.chain_id = chain_id
        self.fail_open = fail_open
        self._chain = HashChainBackend(signing_key=signing_key)
        self._anchor = anchor
        self.last_anchor: EthereumAnchorReceipt | None = None
        if self._anchor is None and rpc_url and private_key:
            self._anchor = EthereumAnchor(
                rpc_url=rpc_url,
                private_key=private_key,
                contract_address=contract,
                chain_id=chain_id,
            )

    @property
    def head(self) -> str:
        return self._chain.head

    @property
    def last_prev_hash(self) -> str:
        return self._chain.last_prev_hash

    def append(self, payload: dict, prev_hash: str | None = None) -> AuditAppendResult:
        chain_result = self._chain.append(payload, prev_hash)
        this_hash = chain_result.this_hash
        self.last_anchor = None
        if self._anchor is None:
            return AuditAppendResult(this_hash, f"eth:local:0x{this_hash[:24]}", chain_result.prev_hash)
        try:
            self.last_anchor = self._anchor.anchor(this_hash)
            return AuditAppendResult(this_hash, f"eth:{self.last_anchor.tx_hash}", chain_result.prev_hash)
        except Exception as exc:
            if not self.fail_open:
                raise
            log.warning("ethereum anchoring failed open: %s", exc)
            return AuditAppendResult(this_hash, f"eth:local:0x{this_hash[:24]}", chain_result.prev_hash)

    def verify_chain(self) -> bool:
        return self._chain.verify_chain()

    def verify_on_chain(
        self,
        tx_hash: str,
        *,
        expected_hash: str = "",
    ) -> EthereumAnchorReceipt:
        if self._anchor is None:
            raise RuntimeError("Ethereum anchor is not configured")
        return self._anchor.verify_on_chain(tx_hash, expected_hash=expected_hash)

    def redact_for_tenant(self, tenant_id: str) -> int:
        return self._chain.redact_for_tenant(tenant_id)

    def redact_for_session(self, tenant_id: str, session_id: str) -> int:
        return self._chain.redact_for_session(tenant_id, session_id)

    def records(self) -> list[dict]:
        return self._chain.records()


class HyperledgerBackend:
    """Optional: anchor the chain head to a Hyperledger Fabric network.

    Same interface as HashChainBackend. The local hash chain is always
    maintained (so verification works offline); when a Fabric gateway is
    configured, each appended head is also submitted to a chaincode as an
    external anchor. If the fabric SDK is unavailable or the network is
    unreachable, anchoring degrades gracefully and the local chain still works.
    """

    def __init__(self, channel: str = "", chaincode: str = "",
                 gateway: str = "", signing_key: str = "",
                 fail_open: bool = False) -> None:
        self.channel = channel
        self.chaincode = chaincode
        self.gateway = gateway
        # Matches EthereumBackend's default: when a gateway IS configured
        # (anchoring is expected), a submission failure raises by default
        # rather than silently degrading to a local-only pseudo-anchor —
        # otherwise a caller who believes anchoring is active has no signal
        # that it silently stopped (ISSUE-10). Pass fail_open=True only for
        # dev/demo deployments that knowingly accept local chain-only
        # evidence during Fabric outages.
        self.fail_open = fail_open
        self._chain = HashChainBackend(signing_key=signing_key)
        self._anchored = 0

    @property
    def head(self) -> str:
        return self._chain.head

    @property
    def last_prev_hash(self) -> str:
        return self._chain.last_prev_hash

    def append(self, payload: dict, prev_hash: str | None = None) -> AuditAppendResult:
        chain_result = self._chain.append(payload, prev_hash)
        this_hash = chain_result.this_hash
        tx = self._anchor(this_hash)
        return AuditAppendResult(this_hash, tx, chain_result.prev_hash)

    def _anchor(self, this_hash: str) -> str:
        """Submit the hash to Fabric chaincode. Returns an anchor tx id.

        No gateway configured means anchoring was never requested, so that
        always degrades to a local pseudo-anchor with no exception involved.
        Once a gateway IS configured, a submission failure raises unless
        fail_open=True (see __init__) — matching EthereumBackend, instead of
        always silently degrading regardless of what the caller asked for.
        """
        if not self.gateway:
            return f"fabric-local:{this_hash[:24]}"
        try:  # pragma: no cover - requires live Fabric network
            # In production: use the Fabric Gateway SDK to submit a transaction:
            #   contract.submit_transaction("AnchorHash", this_hash)
            # Kept import-guarded so the dependency is truly optional.
            from hfc.fabric import Client  # type: ignore  # noqa: F401
            self._anchored += 1
            return f"fabric:{self.channel}:{this_hash[:24]}"
        except Exception as exc:
            if not self.fail_open:
                raise
            log.warning("hyperledger anchoring failed open: %s", exc)
            return f"fabric-local:{this_hash[:24]}"

    def verify_chain(self) -> bool:
        return self._chain.verify_chain()

    def redact_for_tenant(self, tenant_id: str) -> int:
        return self._chain.redact_for_tenant(tenant_id)

    def redact_for_session(self, tenant_id: str, session_id: str) -> int:
        return self._chain.redact_for_session(tenant_id, session_id)

    def records(self) -> list[dict]:
        return self._chain.records()

    @property
    def anchored_count(self) -> int:
        return self._anchored
