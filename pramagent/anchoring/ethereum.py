"""
pramagent.anchoring.ethereum
============================
Real Ethereum/Sepolia anchoring for Pramagent audit heads.

The default strategy does not require a custom smart contract: it sends a
zero-value transaction to the configured contract address, or back to the
signing account when no contract is supplied, with the trace hash in calldata.
That gives a public timestamped receipt without forcing Solidity into the MVP.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional


SEPOLIA_CHAIN_ID = 11155111


class EthereumAnchorError(RuntimeError):
    """Raised when Ethereum anchoring cannot complete."""


@dataclass(frozen=True)
class EthereumAnchorReceipt:
    tx_hash: str
    block_number: int
    status: int
    chain_id: int
    anchored_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "status": self.status,
            "chain_id": self.chain_id,
            "anchored_hash": self.anchored_hash,
        }


class EthereumAnchor:
    """Anchor SHA-256 trace heads to Ethereum-compatible chains.

    Parameters are explicit so production callers can wire secrets from a real
    secret manager. Tests can pass a fake Web3-like object through ``web3``.
    """

    def __init__(
        self,
        *,
        rpc_url: str = "",
        private_key: str = "",
        contract_address: str = "",
        chain_id: int = SEPOLIA_CHAIN_ID,
        web3: Optional[Any] = None,
        gas_limit: int = 50_000,
        wait_timeout: int = 300,
        poll_latency: int = 5,
    ) -> None:
        self.rpc_url = rpc_url
        self.private_key = private_key
        self.contract_address = contract_address
        self.chain_id = chain_id
        self.gas_limit = gas_limit
        self.wait_timeout = wait_timeout
        self.poll_latency = poll_latency
        self._w3 = web3 or self._load_web3(rpc_url)
        if not private_key:
            raise EthereumAnchorError("private_key is required for Ethereum anchoring")
        self._account = self._w3.eth.account.from_key(private_key)
        # get_transaction_count → sign → send must be one critical section or
        # concurrent anchors race the nonce and overwrite each other.
        self._nonce_lock = threading.Lock()

    @staticmethod
    def _load_web3(rpc_url: str) -> Any:
        if not rpc_url:
            raise EthereumAnchorError("rpc_url is required for Ethereum anchoring")
        try:
            from web3 import Web3  # type: ignore
        except ImportError as exc:
            raise EthereumAnchorError(
                "web3 is not installed; install with: pip install 'pramagent[ethereum]'"
            ) from exc
        return Web3(Web3.HTTPProvider(rpc_url))

    def anchor(self, trace_hash: str, *, wait_for_receipt: bool = False) -> EthereumAnchorReceipt:
        """Submit an anchoring transaction.

        Default is submit-and-return: the receipt comes back with status=-1
        (submitted, unconfirmed) and block_number=0 immediately — mining can
        take minutes and must never stall the request path.
        Confirmation is reconciled out-of-band via verify_on_chain() (or pass
        wait_for_receipt=True from a background job).
        """
        clean_hash = _normalize_trace_hash(trace_hash)
        to_address = self.contract_address or self._account.address
        with self._nonce_lock:
            nonce = self._w3.eth.get_transaction_count(self._account.address)
            tx = {
                "to": to_address,
                "value": 0,
                "data": "0x" + clean_hash,
                "nonce": nonce,
                "chainId": self.chain_id,
                "gas": self.gas_limit,
            }
            tx.update(_fee_fields(self._w3))
            signed = self._w3.eth.account.sign_transaction(tx, self.private_key)
            raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
            tx_hash_raw = self._w3.eth.send_raw_transaction(raw)
        tx_hash = _to_hex(self._w3, tx_hash_raw)
        if not wait_for_receipt:
            return EthereumAnchorReceipt(
                tx_hash=tx_hash,
                block_number=0,
                status=-1,          # -1 = submitted, unconfirmed
                chain_id=self.chain_id,
                anchored_hash=clean_hash,
            )
        receipt = self._w3.eth.wait_for_transaction_receipt(
            tx_hash,
            timeout=self.wait_timeout,
            poll_latency=self.poll_latency,
        )
        block_number = _get_receipt_value(receipt, "blockNumber", "block_number", default=0)
        status = _get_receipt_value(receipt, "status", default=0)
        return EthereumAnchorReceipt(
            tx_hash=tx_hash,
            block_number=int(block_number or 0),
            status=int(status or 0),
            chain_id=self.chain_id,
            anchored_hash=clean_hash,
        )

    def verify_on_chain(
        self,
        tx_hash: str,
        *,
        expected_hash: str = "",
    ) -> EthereumAnchorReceipt:
        normalized_tx = tx_hash.removeprefix("eth:").removeprefix("sepolia:")
        receipt = self._w3.eth.get_transaction_receipt(normalized_tx)
        tx = self._w3.eth.get_transaction(normalized_tx)
        status = int(_get_receipt_value(receipt, "status", default=0) or 0)
        block_number = int(
            _get_receipt_value(receipt, "blockNumber", "block_number", default=0) or 0
        )
        input_data = _calldata_to_hex(_get_receipt_value(tx, "input", "data", default=""))
        anchored_hash = expected_hash.removeprefix("0x").lower()
        if status != 1:
            raise EthereumAnchorError(f"transaction {normalized_tx} did not succeed")
        if anchored_hash and anchored_hash not in input_data.lower():
            raise EthereumAnchorError("transaction calldata does not contain expected hash")
        return EthereumAnchorReceipt(
            tx_hash=normalized_tx,
            block_number=block_number,
            status=status,
            chain_id=self.chain_id,
            anchored_hash=anchored_hash,
        )


def _normalize_trace_hash(trace_hash: str) -> str:
    clean = trace_hash.removeprefix("0x").lower()
    if len(clean) != 64:
        raise EthereumAnchorError("trace_hash must be a 32-byte hex SHA-256 digest")
    try:
        bytes.fromhex(clean)
    except ValueError as exc:
        raise EthereumAnchorError("trace_hash must be valid hex") from exc
    return clean


def _to_hex(w3: Any, value: Any) -> str:
    if isinstance(value, str):
        return value
    if hasattr(w3, "to_hex"):
        return w3.to_hex(value)
    if hasattr(value, "hex"):
        h = value.hex()
        return h if h.startswith("0x") else f"0x{h}"
    raise EthereumAnchorError("could not convert transaction hash to hex")


def _fee_fields(w3: Any) -> dict[str, int]:
    gas_price = int(w3.eth.gas_price)
    try:
        latest = w3.eth.get_block("latest")
        base_fee = _get_receipt_value(latest, "baseFeePerGas", "base_fee_per_gas")
    except Exception:
        base_fee = None
    if base_fee is None:
        return {"gasPrice": max(gas_price, 1)}

    priority_fee = max(int(gas_price * 0.15), 1_000_000_000)
    max_fee = max(int(gas_price * 2), int(base_fee) * 2 + priority_fee)
    return {
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
    }


def _calldata_to_hex(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        h = value.hex()
        return h.lower() if str(h).startswith("0x") else f"0x{h}".lower()
    return str(value).lower()


def _get_receipt_value(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return default
