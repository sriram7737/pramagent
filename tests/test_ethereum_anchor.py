import asyncio

import pytest

from pramagent import Pramagent
from pramagent.audit import EthereumBackend
from pramagent.anchoring.ethereum import EthereumAnchor, EthereumAnchorError
from pramagent.providers import MockProvider


class _Signed:
    raw_transaction = b"signed-tx"


class _Account:
    address = "0xabc0000000000000000000000000000000000000"


class _AccountApi:
    def from_key(self, key):
        return _Account()

    def sign_transaction(self, tx, key):
        self.last_tx = tx
        return _Signed()


class _Eth:
    def __init__(self):
        self.account = _AccountApi()
        self.gas_price = 10
        self.sent_raw = None
        self.receipt = {"blockNumber": 123, "status": 1}
        self.tx = {"input": "0x" + "a" * 64}

    def get_transaction_count(self, address):
        return 7

    def send_raw_transaction(self, raw):
        self.sent_raw = raw
        return b"\x12" * 32

    def wait_for_transaction_receipt(self, tx_hash, **kwargs):
        return self.receipt

    def get_transaction_receipt(self, tx_hash):
        return self.receipt

    def get_transaction(self, tx_hash):
        return {"input": bytes.fromhex(self.account.last_tx["data"].removeprefix("0x"))}


class _Web3:
    def __init__(self):
        self.eth = _Eth()

    def to_hex(self, value):
        return "0x" + value.hex()


def test_ethereum_anchor_submits_hash_as_calldata():
    w3 = _Web3()
    anchor = EthereumAnchor(web3=w3, private_key="secret")

    receipt = anchor.anchor("a" * 64)

    assert receipt.tx_hash == "0x" + "12" * 32
    # default is submit-and-return: never wait for mining on the hot path
    # ; -1 = submitted, unconfirmed
    assert receipt.block_number == 0
    assert receipt.status == -1
    assert w3.eth.account.last_tx["data"] == "0x" + "a" * 64
    assert w3.eth.account.last_tx["gasPrice"] == 10
    assert w3.eth.sent_raw == b"signed-tx"


def test_ethereum_anchor_waits_for_receipt_only_on_request():
    """Background reconciliation jobs can opt into the blocking wait."""
    w3 = _Web3()
    anchor = EthereumAnchor(web3=w3, private_key="secret")

    receipt = anchor.anchor("a" * 64, wait_for_receipt=True)

    assert receipt.block_number == 123
    assert receipt.status == 1


def test_ethereum_anchor_uses_eip1559_fee_fields_when_available():
    class _Eip1559Eth(_Eth):
        def get_block(self, name):
            return {"baseFeePerGas": 20}

    class _Eip1559Web3(_Web3):
        def __init__(self):
            self.eth = _Eip1559Eth()

    w3 = _Eip1559Web3()
    anchor = EthereumAnchor(web3=w3, private_key="secret")

    anchor.anchor("a" * 64)

    assert "gasPrice" not in w3.eth.account.last_tx
    assert w3.eth.account.last_tx["maxFeePerGas"] >= 1_000_000_040
    assert w3.eth.account.last_tx["maxPriorityFeePerGas"] >= 1_000_000_000


def test_ethereum_anchor_rejects_non_hash():
    anchor = EthereumAnchor(web3=_Web3(), private_key="secret")

    with pytest.raises(EthereumAnchorError):
        anchor.anchor("not-a-sha")


def test_ethereum_backend_records_real_anchor_metadata():
    anchor = EthereumAnchor(web3=_Web3(), private_key="secret")
    backend = EthereumBackend(anchor=anchor)

    trace_hash, tx_hash = backend.append({"hello": "world"})

    assert tx_hash.startswith("eth:0x")
    assert backend.last_anchor is not None
    # hot path submits without waiting for mining ; confirmation
    # is reconciled out-of-band via verify_on_chain
    assert backend.last_anchor.status == -1
    assert backend.last_anchor.block_number == 0
    assert backend.verify_on_chain(tx_hash, expected_hash=trace_hash).status == 1


def test_trace_stores_anchor_block_number_from_backend():
    armor = Pramagent(
        provider=MockProvider(),
        audit=EthereumBackend(anchor=EthereumAnchor(web3=_Web3(), private_key="secret")),
    )

    response = asyncio.run(armor.run("hello", tenant_id="t", session_id="s"))

    assert response.trace.anchor_tx_id.startswith("eth:0x")
    # unconfirmed at write time — the request never waits for mining
    assert response.trace.anchor_block_number == 0
    assert response.trace.anchor_metadata["status"] == -1
    assert response.trace.anchor_metadata["tx_hash"].startswith("0x")


def test_ethereum_backend_does_not_reuse_stale_anchor_after_fail_open():
    class _FlakyAnchor:
        def __init__(self):
            self.calls = 0

        def anchor(self, trace_hash):
            self.calls += 1
            if self.calls == 1:
                return EthereumAnchor(web3=_Web3(), private_key="secret").anchor(trace_hash)
            raise RuntimeError("temporary chain outage")

    backend = EthereumBackend(anchor=_FlakyAnchor(), fail_open=True)

    _, first_tx = backend.append({"n": 1})
    _, second_tx = backend.append({"n": 2})

    assert first_tx.startswith("eth:0x")
    assert second_tx.startswith("eth:local:0x")
    assert backend.last_anchor is None
