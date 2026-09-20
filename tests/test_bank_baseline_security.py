from __future__ import annotations

import sys
from pathlib import Path


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "bank_baseline"
sys.path.insert(0, str(EXAMPLE))
from baseline import Controller, MockBank, Task


TOKEN = "synthetic-operator-token-for-tests-only"


def test_bank_task_is_default_deny():
    task = Task()
    assert task.can_transfer is False
    assert task.allowed_operations == ()
    assert task.readable_accounts == ()
    assert task.permits("bank.balance") is False


def test_bank_lists_only_task_authorized_resources(tmp_path):
    bank = MockBank(tmp_path / "bank.sqlite")
    controller = Controller(
        tmp_path / "control", bank, operator_token=TOKEN,
        clock=lambda: 1_800_000_000,
    )
    task = Task(
        can_transfer=False,
        allowed_operations=("bank.list_accounts",),
        readable_accounts=("a-main",),
    )
    controller.configure(task, TOKEN)
    try:
        result = controller.submit(task.task_id, {
            "operation_id": "list-1",
            "tool": "bank.list_accounts",
            "arguments": {},
        })
        assert result["status"] == "completed"
        assert [row["id"] for row in result["result"]["accounts"]] == ["a-main"]
    finally:
        controller.close()
        bank.close()


def test_schedule_horizon_is_enforced_from_controller_time(tmp_path):
    now = 1_800_000_000
    bank = MockBank(tmp_path / "bank.sqlite")
    controller = Controller(
        tmp_path / "control", bank, operator_token=TOKEN, clock=lambda: now,
    )
    task = Task(
        can_transfer=True,
        allowed_operations=("bank.schedule_transfer",),
        readable_accounts=("a-main",),
        max_schedule_horizon=60,
    )
    controller.configure(task, TOKEN)
    try:
        result = controller.submit(task.task_id, {
            "operation_id": "schedule-1",
            "tool": "bank.schedule_transfer",
            "arguments": {
                "source": "a-main", "destination": "a-vendor",
                "amount_cents": 1000, "execute_at": now + 61,
            },
        })
        assert result["code"] == "SCHEDULE_HORIZON_EXCEEDED"
    finally:
        controller.close()
        bank.close()


def test_bank_rejects_cross_tenant_refund_even_when_controller_scope_is_wrong(tmp_path):
    bank = MockBank(tmp_path / "bank.sqlite")
    try:
        victim = bank.request("transfer_external", {
            "operation_id": "victim-payment",
            "tenant": "tenant-b",
            "source": "b-main",
            "payee_id": "victim-payee",
            "amount_cents": 12_345,
        })
        assert victim["ok"] is True

        attack = bank.request("refund", {
            "operation_id": "attacker-refund",
            "operation_ref": "victim-payment",
            "tenant": "tenant-a",
            "destination": "a-main",
            "expected_amount_cents": 12_345,
        })
        assert attack == {"ok": False, "code": "BANK_RECORD_SCOPE"}
    finally:
        bank.close()
